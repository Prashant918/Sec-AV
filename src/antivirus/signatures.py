import hashlib
import re
import requests
import time
import os
import sys
import json
import threading
import subprocess
import tempfile
import zipfile
import glob
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path
from collections import defaultdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import psutil
from datetime import datetime, timedelta

# Conditional imports for platform-specific functionality
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: YARA not available. Pattern matching will be limited.")

try:
    import magic

    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. File type detection will be limited.")

# Windows-specific imports
if os.name == "nt":
    try:
        import winreg
        import ctypes
        from ctypes import wintypes

        WINDOWS_API_AVAILABLE = True
    except ImportError:
        WINDOWS_API_AVAILABLE = False
        print("Warning: Windows API modules not available.")
else:
    WINDOWS_API_AVAILABLE = False

from .config import secure_config
from .logger import SecureLogger
from .database import db_manager


class SignatureEncryption:
    """Handle encryption/decryption of signature database"""

    def __init__(self, password: bytes = None):
        if password is None:
            password = b"default_signature_key_change_in_production"

        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher_suite = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        return self.cipher_suite.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data"""
        return self.cipher_suite.decrypt(encrypted_data)


class ThreatIntelligence:
    """Threat intelligence integration with secure API handling"""

    def __init__(self):
        self.logger = SecureLogger("ThreatIntel")
        self.intel_sources = {
            "virustotal": "https://www.virustotal.com/vtapi/v2/",
            "malware_bazaar": "https://mb-api.abuse.ch/api/v1/",
            "hybrid_analysis": "https://www.hybrid-analysis.com/api/v2/",
        }
        self.api_keys = self._load_api_keys()
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour
        self.rate_limits = {
            "virustotal": {
                "requests": 0,
                "reset_time": 0,
                "limit": 4,
            }  # 4 requests per minute
        }

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from secure configuration"""
        try:
            config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "config")
            os.makedirs(config_dir, exist_ok=True)
            keys_file = os.path.join(config_dir, "api_keys.json")

            if os.path.exists(keys_file):
                with open(keys_file, "r") as f:
                    return json.load(f)
            else:
                # Create empty API keys file
                default_keys = {
                    "virustotal": "",
                    "malware_bazaar": "",
                    "hybrid_analysis": "",
                }
                with open(keys_file, "w") as f:
                    json.dump(default_keys, f, indent=2)
                os.chmod(keys_file, 0o600)
                self.logger.info(
                    "Created empty API keys file. Please add your API keys."
                )
                return default_keys
        except Exception as e:
            self.logger.error(f"Failed to load API keys: {e}")
            return {}

    def query_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Query hash reputation from threat intelligence sources"""
        # Check cache first
        cache_key = f"hash_{file_hash}"
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            if time.time() - cached_data["timestamp"] < self.cache_timeout:
                return cached_data["data"]

        reputation_data = {
            "hash": file_hash,
            "malicious": False,
            "detections": 0,
            "total_scans": 0,
            "sources": [],
            "threat_names": [],
            "first_seen": None,
            "last_seen": None,
        }

        # Query VirusTotal if API key is available
        if self.api_keys.get("virustotal"):
            vt_data = self._query_virustotal(file_hash)
            if vt_data:
                reputation_data["sources"].append("virustotal")
                reputation_data["detections"] += vt_data.get("positives", 0)
                reputation_data["total_scans"] += vt_data.get("total", 0)
                if vt_data.get("positives", 0) > 0:
                    reputation_data["malicious"] = True
                    scans = vt_data.get("scans", {})
                    for engine, result in scans.items():
                        if result.get("result") and result["result"] != "None":
                            reputation_data["threat_names"].append(result["result"])

        # Cache results
        self.cache[cache_key] = {"data": reputation_data, "timestamp": time.time()}

        return reputation_data

    def _query_virustotal(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal API with rate limiting"""
        try:
            api_key = self.api_keys.get("virustotal")
            if not api_key:
                return None

            # Check rate limiting
            current_time = time.time()
            rate_limit = self.rate_limits["virustotal"]

            if current_time > rate_limit["reset_time"]:
                rate_limit["requests"] = 0
                rate_limit["reset_time"] = current_time + 60  # Reset every minute

            if rate_limit["requests"] >= rate_limit["limit"]:
                self.logger.warning("VirusTotal rate limit exceeded")
                return None

            url = f"{self.intel_sources['virustotal']}file/report"
            params = {"apikey": api_key, "resource": file_hash}

            response = requests.get(url, params=params, timeout=10)
            rate_limit["requests"] += 1

            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 1:
                    return data
            elif response.status_code == 204:
                self.logger.warning("VirusTotal API rate limit exceeded")

        except Exception as e:
            self.logger.warning(f"VirusTotal query failed: {e}")

        return None


class YaraRuleManager:
    """Manage YARA rules for pattern matching"""

    def __init__(self):
        self.logger = SecureLogger("YaraManager")
        data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data")
        self.rules_dir = os.path.join(data_dir, "yara_rules")
        self.compiled_rules = None
        self.rule_sources = {}
        self._ensure_rules_directory()
        if YARA_AVAILABLE:
            self._load_default_rules()
        else:
            self.logger.warning("YARA not available - rule-based detection disabled")

    def _ensure_rules_directory(self):
        """Ensure YARA rules directory exists"""
        os.makedirs(self.rules_dir, exist_ok=True)

    def _load_default_rules(self):
        """Load default YARA rules"""
        if not YARA_AVAILABLE:
            return

        default_rules = {
            "malware_generic.yar": """
rule Generic_Malware_Strings
{
    meta:
        description = "Generic malware string patterns"
        author = "Advanced Antivirus"
        date = "2024-01-01"
    
    strings:
        $s1 = "backdoor" nocase
        $s2 = "keylogger" nocase
        $s3 = "trojan" nocase
        $s4 = "rootkit" nocase
        $s5 = "ransomware" nocase
        $s6 = "cryptolocker" nocase
        $s7 = "payload" nocase
        $s8 = "shellcode" nocase
    
    condition:
        any of them
}

rule Suspicious_API_Calls
{
    meta:
        description = "Suspicious Windows API calls"
        author = "Advanced Antivirus"
    
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "SetWindowsHookEx"
        $api5 = "GetAsyncKeyState"
        $api6 = "CryptEncrypt"
        $api7 = "RegSetValueEx"
    
    condition:
        3 of them
}
""",
            "ransomware.yar": """
rule Ransomware_Indicators
{
    meta:
        description = "Ransomware behavior indicators"
        author = "Advanced Antivirus"
    
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = ".locked" nocase
        $r6 = ".encrypted" nocase
        $r7 = "payment" nocase
        $r8 = "restore your files" nocase
    
    condition:
        3 of them
}
""",
            "keylogger.yar": """
rule Keylogger_Patterns
{
    meta:
        description = "Keylogger detection patterns"
        author = "Advanced Antivirus"
    
    strings:
        $k1 = "GetAsyncKeyState"
        $k2 = "SetWindowsHookEx"
        $k3 = "WH_KEYBOARD_LL"
        $k4 = "keylog" nocase
        $k5 = "keystroke" nocase
        $k6 = "GetKeyboardState"
    
    condition:
        2 of them
}
""",
        }

        for rule_name, rule_content in default_rules.items():
            rule_path = os.path.join(self.rules_dir, rule_name)
            if not os.path.exists(rule_path):
                with open(rule_path, "w") as f:
                    f.write(rule_content)

        self._compile_rules()

    def _compile_rules(self):
        """Compile all YARA rules"""
        if not YARA_AVAILABLE:
            return

        try:
            rule_files = {}
            for filename in os.listdir(self.rules_dir):
                if filename.endswith(".yar") or filename.endswith(".yara"):
                    rule_path = os.path.join(self.rules_dir, filename)
                    rule_files[filename] = rule_path

            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                self.logger.info(f"Compiled {len(rule_files)} YARA rules")
            else:
                self.logger.warning("No YARA rules found")

        except Exception as e:
            self.logger.error(f"YARA rule compilation failed: {e}")

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        matches = []

        if not YARA_AVAILABLE or not self.compiled_rules:
            return matches

        try:
            yara_matches = self.compiled_rules.match(file_path)

            for match in yara_matches:
                match_info = {
                    "rule_name": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [],
                }

                # Extract matched strings
                for string_match in match.strings:
                    match_info["strings"].append(
                        {
                            "identifier": string_match.identifier,
                            "instances": [
                                {
                                    "offset": instance.offset,
                                    "matched_data": instance.matched_data.decode(
                                        "utf-8", errors="ignore"
                                    )[:100],
                                }
                                for instance in string_match.instances
                            ],
                        }
                    )

                matches.append(match_info)

        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")

        return matches

    def add_custom_rule(self, rule_name: str, rule_content: str) -> bool:
        """Add custom YARA rule"""
        if not YARA_AVAILABLE:
            self.logger.error("YARA not available - cannot add custom rules")
            return False

        try:
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
            with open(rule_path, "w") as f:
                f.write(rule_content)

            # Recompile rules
            self._compile_rules()
            self.logger.info(f"Added custom YARA rule: {rule_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add custom rule: {e}")
            return False


class AdvancedSignatureManager:
    """Advanced signature management with Oracle database backend"""

    def __init__(self):
        self.logger = SecureLogger("SignatureManager")
        self.cipher_suite = SignatureEncryption()
        self.threat_intel = ThreatIntelligence()
        self.yara_manager = YaraRuleManager()

        # Signature categories
        self.signature_types = {
            "hash": "File hash signatures",
            "pattern": "Byte pattern signatures",
            "heuristic": "Heuristic signatures",
            "behavioral": "Behavioral signatures",
        }

        self._load_default_signatures()

        # Update configuration
        self.update_interval = 3600  # 1 hour
        self.auto_update = secure_config.get("detection.signature_updates", True)
        self.update_thread = None

        if self.auto_update:
            self._start_update_thread()

    def _load_default_signatures(self):
        """Load default signature set"""
        default_hashes = [
            # Known malware hashes (examples - in real implementation, use actual threat hashes)
            (
                "44d88612fea8a8f36de82e1278abb02f",
                "md5",
                "Test.Malware.Generic",
                "high",
                "default",
            ),
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "sha256",
                "Test.Trojan.Generic",
                "high",
                "default",
            ),
            (
                "d41d8cd98f00b204e9800998ecf8427e",
                "md5",
                "Test.EmptyFile",
                "low",
                "default",
            ),
        ]

        try:
            for file_hash, hash_type, threat_name, severity, source in default_hashes:
                # Use Oracle MERGE statement for upsert functionality
                query = """
                    MERGE INTO hash_signatures hs
                    USING (SELECT :file_hash as file_hash, :hash_type as hash_type FROM DUAL) src
                    ON (hs.file_hash = src.file_hash AND hs.hash_type = src.hash_type)
                    WHEN NOT MATCHED THEN
                        INSERT (file_hash, hash_type, threat_name, severity, source)
                        VALUES (:file_hash, :hash_type, :threat_name, :severity, :source)
                """

                params = {
                    "file_hash": file_hash,
                    "hash_type": hash_type,
                    "threat_name": threat_name,
                    "severity": severity,
                    "source": source,
                }

                db_manager.execute_command(query, params)

            self.logger.info("Default signatures loaded")

        except Exception as e:
            self.logger.error(f"Failed to load default signatures: {e}")

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file scanning using all signature types"""
        scan_results = {
            "file_path": file_path,
            "threats": [],
            "scan_details": {
                "hash_matches": [],
                "pattern_matches": [],
                "yara_matches": [],
                "threat_intel": {},
            },
            "risk_level": "unknown",
        }

        try:
            # Calculate file hashes
            file_hashes = self._calculate_file_hashes(file_path)

            # Hash-based detection
            hash_threats = self._scan_hash_signatures(file_hashes)
            scan_results["threats"].extend(hash_threats)
            scan_results["scan_details"]["hash_matches"] = hash_threats

            # Pattern-based detection
            pattern_threats = self._scan_pattern_signatures(file_path)
            scan_results["threats"].extend(pattern_threats)
            scan_results["scan_details"]["pattern_matches"] = pattern_threats

            # YARA rule scanning
            yara_matches = self.yara_manager.scan_file(file_path)
            for match in yara_matches:
                threat = {
                    "type": "yara_match",
                    "threat_name": match["rule_name"],
                    "severity": self._determine_severity_from_tags(match["tags"]),
                    "description": f"YARA rule {match['rule_name']} matched",
                    "details": match,
                }
                scan_results["threats"].append(threat)
            scan_results["scan_details"]["yara_matches"] = yara_matches

            # Threat intelligence lookup
            if file_hashes.get("sha256"):
                intel_data = self.threat_intel.query_hash_reputation(
                    file_hashes["sha256"]
                )
                scan_results["scan_details"]["threat_intel"] = intel_data

                if intel_data.get("malicious"):
                    threat = {
                        "type": "threat_intelligence",
                        "threat_name": "Multiple.Threat.Intelligence",
                        "severity": (
                            "high" if intel_data["detections"] > 5 else "medium"
                        ),
                        "description": f"Detected by {intel_data['detections']}/{intel_data['total_scans']} engines",
                        "details": intel_data,
                    }
                    scan_results["threats"].append(threat)

            # Calculate overall risk level
            scan_results["risk_level"] = self._calculate_risk_level(
                scan_results["threats"]
            )

            # Store scan results in database
            self._store_scan_results(scan_results, file_hashes)

        except Exception as e:
            self.logger.error(f"File scan failed for {file_path}: {e}")
            scan_results["error"] = str(e)

        return scan_results

    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hash types for file"""
        hashes = {}

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            hashes["md5"] = hashlib.md5(content).hexdigest()
            hashes["sha1"] = hashlib.sha1(content).hexdigest()
            hashes["sha256"] = hashlib.sha256(content).hexdigest()

        except Exception as e:
            self.logger.warning(f"Hash calculation failed: {e}")

        return hashes

    def _scan_hash_signatures(
        self, file_hashes: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Scan against hash signature database"""
        threats = []

        try:
            for hash_type, hash_value in file_hashes.items():
                query = """
                    SELECT threat_name, severity, source 
                    FROM hash_signatures 
                    WHERE file_hash = :file_hash AND hash_type = :hash_type
                """

                params = {"file_hash": hash_value, "hash_type": hash_type}
                results = db_manager.execute_query(query, params)

                for row in results:
                    threats.append(
                        {
                            "type": "hash_signature",
                            "threat_name": row[0],
                            "severity": row[1],
                            "description": f"{hash_type.upper()} hash match: {hash_value}",
                            "source": row[2],
                            "hash_type": hash_type,
                            "hash_value": hash_value,
                        }
                    )

        except Exception as e:
            self.logger.error(f"Hash signature scan failed: {e}")

        return threats

    def _scan_pattern_signatures(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan against pattern signature database"""
        threats = []

        try:
            query = "SELECT pattern, threat_name, severity, offset_pos FROM pattern_signatures"
            patterns = db_manager.execute_query(query)

            with open(file_path, "rb") as f:
                file_content = f.read()

            for row in patterns:
                encrypted_pattern, threat_name, severity, offset = row
                try:
                    # Decrypt pattern
                    pattern = self.cipher_suite.decrypt(encrypted_pattern)

                    # Search for pattern in file
                    if offset > 0:
                        # Search at specific offset
                        if (
                            len(file_content) > offset
                            and file_content[offset : offset + len(pattern)] == pattern
                        ):
                            threats.append(
                                {
                                    "type": "pattern_signature",
                                    "threat_name": threat_name,
                                    "severity": severity,
                                    "description": f"Pattern match at offset {offset}",
                                    "offset": offset,
                                }
                            )
                    else:
                        # Search entire file
                        if pattern in file_content:
                            threats.append(
                                {
                                    "type": "pattern_signature",
                                    "threat_name": threat_name,
                                    "severity": severity,
                                    "description": "Pattern match found in file",
                                    "pattern_length": len(pattern),
                                }
                            )

                except Exception as e:
                    self.logger.warning(f"Pattern decryption failed: {e}")

        except Exception as e:
            self.logger.error(f"Pattern signature scan failed: {e}")

        return threats

    def _store_scan_results(
        self, scan_results: Dict[str, Any], file_hashes: Dict[str, str]
    ):
        """Store scan results in Oracle database"""
        try:
            # Insert scan result
            insert_scan_query = """
                INSERT INTO scan_results 
                (file_path, file_hash, file_size, scan_time, threat_score, classification, scan_details)
                VALUES (:file_path, :file_hash, :file_size, :scan_time, :threat_score, :classification, :scan_details)
            """

            scan_params = {
                "file_path": scan_results["file_path"],
                "file_hash": file_hashes.get("sha256", ""),
                "file_size": (
                    os.path.getsize(scan_results["file_path"])
                    if os.path.exists(scan_results["file_path"])
                    else 0
                ),
                "scan_time": scan_results.get("scan_time", 0),
                "threat_score": self._calculate_threat_score(scan_results["threats"]),
                "classification": scan_results["risk_level"],
                "scan_details": json.dumps(scan_results["scan_details"]),
            }

            db_manager.execute_command(insert_scan_query, scan_params)

            # Get the scan result ID for threat detections
            get_scan_id_query = """
                SELECT id FROM scan_results 
                WHERE file_path = :file_path AND file_hash = :file_hash 
                ORDER BY scan_date DESC 
                FETCH FIRST 1 ROWS ONLY
            """

            scan_id_result = db_manager.execute_query(
                get_scan_id_query,
                {
                    "file_path": scan_results["file_path"],
                    "file_hash": file_hashes.get("sha256", ""),
                },
            )

            if scan_id_result:
                scan_result_id = scan_id_result[0][0]

                # Insert threat detections
                for threat in scan_results["threats"]:
                    insert_threat_query = """
                        INSERT INTO threat_detections 
                        (scan_result_id, detection_type, threat_name, severity, confidence, detection_details)
                        VALUES (:scan_result_id, :detection_type, :threat_name, :severity, :confidence, :detection_details)
                    """

                    threat_params = {
                        "scan_result_id": scan_result_id,
                        "detection_type": threat.get("type", "unknown"),
                        "threat_name": threat.get("threat_name", "Unknown"),
                        "severity": threat.get("severity", "medium"),
                        "confidence": threat.get("confidence", 0.5),
                        "detection_details": json.dumps(threat.get("details", {})),
                    }

                    db_manager.execute_command(insert_threat_query, threat_params)

        except Exception as e:
            self.logger.error(f"Failed to store scan results: {e}")

    def _calculate_threat_score(self, threats: List[Dict[str, Any]]) -> float:
        """Calculate overall threat score"""
        if not threats:
            return 0.0

        # Weighted scoring based on detection method reliability
        weights = {
            "hash_signature": 0.9,
            "pattern_signature": 0.7,
            "yara_match": 0.8,
            "threat_intelligence": 0.85,
        }

        severity_multipliers = {"low": 0.3, "medium": 0.6, "high": 1.0, "critical": 1.2}

        total_score = 0.0
        total_weight = 0.0

        for threat in threats:
            threat_type = threat.get("type", "unknown")
            severity = threat.get("severity", "medium")

            weight = weights.get(threat_type, 0.5)
            severity_mult = severity_multipliers.get(severity, 0.6)

            score = weight * severity_mult
            total_score += score
            total_weight += weight

        if total_weight > 0:
            return min(total_score / total_weight, 1.0)

        return 0.0

    def _determine_severity_from_tags(self, tags: List[str]) -> str:
        """Determine severity based on YARA rule tags"""
        if "critical" in tags or "high" in tags:
            return "high"
        elif "medium" in tags or "suspicious" in tags:
            return "medium"
        elif "low" in tags or "info" in tags:
            return "low"
        else:
            return "medium"  # Default

    def _calculate_risk_level(self, threats: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on detected threats"""
        if not threats:
            return "safe"

        high_count = sum(1 for t in threats if t.get("severity") == "high")
        medium_count = sum(1 for t in threats if t.get("severity") == "medium")

        if high_count > 0:
            return "high"
        elif medium_count > 2:
            return "high"
        elif medium_count > 0:
            return "medium"
        else:
            return "low"

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if hash exists in signature database"""
        try:
            query = """
                SELECT threat_name, severity, source, hash_type
                FROM hash_signatures 
                WHERE file_hash = :file_hash
            """

            result = db_manager.execute_query(query, {"file_hash": file_hash})

            if result:
                row = result[0]
                return {
                    "family": row[0],
                    "severity": row[1],
                    "source": row[2],
                    "hash_type": row[3],
                }

            return None

        except Exception as e:
            self.logger.error(f"Hash check failed: {e}")
            return None

    def check_fuzzy_hash(self, fuzzy_hash: str) -> List[Dict[str, Any]]:
        """Check fuzzy hash similarity (placeholder implementation)"""
        # This would require ssdeep or similar fuzzy hashing library
        # For now, return empty list
        return []

    def add_hash_signature(
        self,
        file_hash: str,
        hash_type: str,
        threat_name: str,
        severity: str,
        source: str = "manual",
    ) -> bool:
        """Add new hash signature to database"""
        try:
            query = """
                MERGE INTO hash_signatures hs
                USING (SELECT :file_hash as file_hash, :hash_type as hash_type FROM DUAL) src
                ON (hs.file_hash = src.file_hash AND hs.hash_type = src.hash_type)
                WHEN NOT MATCHED THEN
                    INSERT (file_hash, hash_type, threat_name, severity, source)
                    VALUES (:file_hash, :hash_type, :threat_name, :severity, :source)
                WHEN MATCHED THEN
                    UPDATE SET threat_name = :threat_name, severity = :severity, source = :source
            """

            params = {
                "file_hash": file_hash,
                "hash_type": hash_type,
                "threat_name": threat_name,
                "severity": severity,
                "source": source,
            }

            db_manager.execute_command(query, params)

            self.logger.info(f"Added hash signature: {threat_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add hash signature: {e}")
            return False

    def add_pattern_signature(
        self, pattern: bytes, threat_name: str, severity: str, offset: int = 0
    ) -> bool:
        """Add new pattern signature to database"""
        try:
            # Encrypt pattern before storing
            encrypted_pattern = self.cipher_suite.encrypt(pattern)

            query = """
                INSERT INTO pattern_signatures 
                (pattern, pattern_type, threat_name, severity, offset_pos)
                VALUES (:pattern, :pattern_type, :threat_name, :severity, :offset_pos)
            """

            params = {
                "pattern": encrypted_pattern,
                "pattern_type": "binary",
                "threat_name": threat_name,
                "severity": severity,
                "offset_pos": offset,
            }

            db_manager.execute_command(query, params)

            self.logger.info(f"Added pattern signature: {threat_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add pattern signature: {e}")
            return False

    def update_from_cloud(self) -> bool:
        """Update signature database from cloud intelligence"""
        try:
            self.logger.info("Starting signature update from cloud...")

            update_count = 0

            # Update from threat intelligence feeds
            update_count += self._update_from_threat_feeds()

            # Update YARA rules
            if self._update_yara_rules():
                update_count += 1

            # Record update in history
            self._record_update(update_count)

            self.logger.info(
                f"Cloud signature update completed. {update_count} updates applied."
            )
            return True

        except Exception as e:
            self.logger.error(f"Cloud signature update failed: {e}")
            return False

    def _update_from_threat_feeds(self) -> int:
        """Update signatures from threat intelligence feeds"""
        update_count = 0

        try:
            # Example: Update from public malware hash feeds
            # In production, use real threat intelligence feeds
            sample_feeds = [
                # These are example URLs - replace with real threat feeds
                # 'https://example.com/malware_hashes.txt',
                # 'https://example.com/threat_signatures.json'
            ]

            for feed_url in sample_feeds:
                try:
                    response = requests.get(feed_url, timeout=30)
                    if response.status_code == 200:
                        # Process feed data (implementation depends on feed format)
                        if feed_url.endswith(".txt"):
                            update_count += self._process_hash_feed(response.text)
                        elif feed_url.endswith(".json"):
                            update_count += self._process_json_feed(response.json())

                except Exception as e:
                    self.logger.warning(f"Failed to update from {feed_url}: {e}")

        except Exception as e:
            self.logger.error(f"Threat feed update failed: {e}")

        return update_count

    def _process_hash_feed(self, feed_content: str) -> int:
        """Process hash feed content"""
        update_count = 0

        try:
            for line in feed_content.strip().split("\n"):
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) >= 3:
                        file_hash, threat_name, severity = parts[:3]
                        hash_type = "sha256" if len(file_hash.strip()) == 64 else "md5"

                        query = """
                            MERGE INTO hash_signatures hs
                            USING (SELECT :file_hash as file_hash, :hash_type as hash_type FROM DUAL) src
                            ON (hs.file_hash = src.file_hash AND hs.hash_type = src.hash_type)
                            WHEN NOT MATCHED THEN
                                INSERT (file_hash, hash_type, threat_name, severity, source)
                                VALUES (:file_hash, :hash_type, :threat_name, :severity, :source)
                        """

                        params = {
                            "file_hash": file_hash.strip(),
                            "hash_type": hash_type,
                            "threat_name": threat_name.strip(),
                            "severity": severity.strip(),
                            "source": "threat_feed",
                        }

                        db_manager.execute_command(query, params)

                        if db_manager.rowcount > 0:
                            update_count += 1

            self.logger.info(f"Processed {update_count} hashes from feed")

        except Exception as e:
            self.logger.error(f"Hash feed processing failed: {e}")

        return update_count

    def _process_json_feed(self, feed_data: Dict) -> int:
        """Process JSON feed content"""
        update_count = 0

        try:
            for item in feed_data.get("signatures", []):
                if item.get("type") == "hash":
                    query = """
                        MERGE INTO hash_signatures hs
                        USING (SELECT :file_hash as file_hash, :hash_type as hash_type FROM DUAL) src
                        ON (hs.file_hash = src.file_hash AND hs.hash_type = src.hash_type)
                        WHEN NOT MATCHED THEN
                            INSERT (file_hash, hash_type, threat_name, severity, source)
                            VALUES (:file_hash, :hash_type, :threat_name, :severity, :source)
                    """

                    params = {
                        "file_hash": item["hash"],
                        "hash_type": item.get("hash_type", "sha256"),
                        "threat_name": item["threat_name"],
                        "severity": item.get("severity", "medium"),
                        "source": "json_feed",
                    }

                    db_manager.execute_command(query, params)

                    if db_manager.rowcount > 0:
                        update_count += 1

            self.logger.info(f"Processed {update_count} hashes from JSON feed")

        except Exception as e:
            self.logger.error(f"JSON feed processing failed: {e}")

        return update_count

    def _update_yara_rules(self) -> bool:
        """Update YARA rules from external sources"""
        if not YARA_AVAILABLE:
            return False

        try:
            # Example YARA rule sources (replace with real sources)
            rule_sources = [
                # 'https://github.com/Yara-Rules/rules/archive/master.zip',
                # 'https://example.com/custom_rules.zip'
            ]

            for source_url in rule_sources:
                try:
                    if self.yara_manager.update_rules_from_source(source_url):
                        self.logger.info(f"Updated YARA rules from {source_url}")
                        return True
                except Exception as e:
                    self.logger.warning(
                        f"YARA rule update failed from {source_url}: {e}"
                    )

            return False

        except Exception as e:
            self.logger.error(f"YARA rule update failed: {e}")
            return False

    def _record_update(self, update_count: int):
        """Record update in history"""
        try:
            query = """
                INSERT INTO update_history 
                (update_type, signatures_added, update_source)
                VALUES (:update_type, :signatures_added, :update_source)
            """

            params = {
                "update_type": "automatic",
                "signatures_added": update_count,
                "update_source": "cloud_intelligence",
            }

            db_manager.execute_command(query, params)

            self.logger.info(f"Recorded {update_count} updates in history")

        except Exception as e:
            self.logger.error(f"Failed to record update: {e}")

    def _start_update_thread(self):
        """Start automatic update thread"""

        def update_worker():
            while self.auto_update:
                try:
                    time.sleep(self.update_interval)
                    self.update_from_cloud()
                except Exception as e:
                    self.logger.error(f"Auto-update failed: {e}")

        self.update_thread = threading.Thread(target=update_worker, daemon=True)
        self.update_thread.start()
        self.logger.info("Auto-update thread started")

    def get_signature_count(self) -> int:
        """Get total signature count"""
        try:
            query = "SELECT COUNT(*) FROM hash_signatures"
            hash_count = db_manager.execute_query(query)[0][0]

            query = "SELECT COUNT(*) FROM pattern_signatures"
            pattern_count = db_manager.execute_query(query)[0][0]

            return hash_count + pattern_count

        except Exception as e:
            self.logger.error(f"Failed to get signature count: {e}")
            return 0

    def get_last_update(self) -> Optional[str]:
        """Get timestamp of last update"""
        try:
            query = "SELECT MAX(update_time) FROM update_history"
            result = db_manager.execute_query(query)
            return result[0][0] if result and result[0][0] else None

        except Exception as e:
            self.logger.error(f"Failed to get last update time: {e}")
            return None

    def get_signature_stats(self) -> Dict[str, Any]:
        """Get signature database statistics"""
        stats = {
            "hash_signatures": 0,
            "pattern_signatures": 0,
            "yara_rules": 0,
            "last_update": None,
            "database_size": 0,
        }

        try:
            query = "SELECT COUNT(*) FROM hash_signatures"
            stats["hash_signatures"] = db_manager.execute_query(query)[0][0]

            query = "SELECT COUNT(*) FROM pattern_signatures"
            stats["pattern_signatures"] = db_manager.execute_query(query)[0][0]

            query = "SELECT MAX(update_time) FROM update_history"
            last_update = db_manager.execute_query(query)
            if last_update:
                stats["last_update"] = last_update[0][0]

            # Get database file size
            if os.path.exists(self.db_path):
                stats["database_size"] = os.path.getsize(self.db_path)

            # Get YARA rules count
            if YARA_AVAILABLE and os.path.exists(self.yara_manager.rules_dir):
                yara_files = [
                    f
                    for f in os.listdir(self.yara_manager.rules_dir)
                    if f.endswith((".yar", ".yara"))
                ]
                stats["yara_rules"] = len(yara_files)

        except Exception as e:
            self.logger.error(f"Failed to get signature stats: {e}")

        return stats
