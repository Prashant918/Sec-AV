import os
import re
import hashlib
import magic
import yara
import pefile
import zipfile
import tarfile
import json
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
import subprocess
import tempfile
import shutil
from collections import defaultdict
import mmap
from .config import Config
from .logger import SecureLogger


class SandboxEnvironment:
    """Secure sandbox for file analysis"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = SecureLogger()
        self.sandbox_dir = None
        self.active_processes = []

    def __enter__(self):
        """Enter sandbox context"""
        self.sandbox_dir = tempfile.mkdtemp(prefix="av_sandbox_")
        os.chmod(self.sandbox_dir, 0o700)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit sandbox context and cleanup"""
        self._cleanup_processes()
        if self.sandbox_dir and os.path.exists(self.sandbox_dir):
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)

    def _cleanup_processes(self):
        """Terminate any spawned processes"""
        for proc in self.active_processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        self.active_processes.clear()

    def analyze_file_safely(self, file_path: str) -> Dict[str, Any]:
        """Analyze file in sandbox environment"""
        if not self.sandbox_dir:
            raise RuntimeError("Sandbox not initialized")

        # Copy file to sandbox
        sandbox_file = os.path.join(self.sandbox_dir, "sample")
        shutil.copy2(file_path, sandbox_file)

        results = {
            "file_operations": [],
            "network_activity": [],
            "registry_changes": [],
            "process_creation": [],
            "suspicious_behavior": [],
        }

        # Monitor file operations
        self._monitor_file_operations(sandbox_file, results)

        return results

    def _monitor_file_operations(self, file_path: str, results: Dict):
        """Monitor file operations during analysis"""
        # Implementation would use OS-specific monitoring
        # This is a simplified version
        try:
            # Use strace on Linux or similar tools
            if os.name == "posix":
                proc = subprocess.Popen(
                    ["strace", "-f", "-e", "trace=file", "file", file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
                self.active_processes.append(proc)
                stdout, stderr = proc.communicate()

                # Parse strace output for suspicious file operations
                for line in stderr.decode().split("\n"):
                    if "openat" in line or "unlink" in line:
                        results["file_operations"].append(line.strip())
        except Exception as e:
            self.logger.log_warning(f"File operation monitoring failed: {str(e)}")


class BehavioralAnalyzer:
    """Advanced behavioral analysis engine"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = SecureLogger()
        self.behavior_patterns = self._load_behavior_patterns()
        self.heuristic_rules = self._load_heuristic_rules()

    def _load_behavior_patterns(self) -> Dict[str, List[str]]:
        """Load behavioral patterns for malware detection"""
        return {
            "ransomware": [
                r"\.encrypt\(",
                r"\.lock\(",
                r"ransom",
                r"bitcoin",
                r"decrypt.*key",
                r"files.*encrypted",
            ],
            "keylogger": [
                r"GetAsyncKeyState",
                r"SetWindowsHookEx",
                r"keylog",
                r"keystroke",
                r"GetKeyboardState",
            ],
            "trojan": [
                r"backdoor",
                r"remote.*access",
                r"shell.*execute",
                r"download.*execute",
                r"persistence",
            ],
            "rootkit": [
                r"hide.*process",
                r"hook.*system",
                r"kernel.*driver",
                r"stealth",
                r"rootkit",
            ],
        }

    def _load_heuristic_rules(self) -> List[Dict]:
        """Load heuristic analysis rules"""
        return [
            {
                "name": "suspicious_api_calls",
                "pattern": r"(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx)",
                "weight": 0.8,
                "category": "process_injection",
            },
            {
                "name": "crypto_functions",
                "pattern": r"(CryptEncrypt|CryptDecrypt|AES|RSA)",
                "weight": 0.6,
                "category": "encryption",
            },
            {
                "name": "network_communication",
                "pattern": r"(socket|connect|send|recv|HttpSendRequest)",
                "weight": 0.4,
                "category": "network",
            },
            {
                "name": "file_manipulation",
                "pattern": r"(DeleteFile|MoveFile|CopyFile|CreateFile)",
                "weight": 0.3,
                "category": "file_ops",
            },
        ]

    def analyze_behavior(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive behavioral analysis"""
        results = {
            "behavioral_score": 0.0,
            "detected_behaviors": [],
            "heuristic_matches": [],
            "risk_indicators": [],
            "malware_family": None,
        }

        try:
            # Extract strings from file
            strings = self._extract_strings(file_path)

            # Analyze behavioral patterns
            for behavior_type, patterns in self.behavior_patterns.items():
                matches = self._match_patterns(strings, patterns)
                if matches:
                    results["detected_behaviors"].append(
                        {
                            "type": behavior_type,
                            "matches": matches,
                            "confidence": len(matches) / len(patterns),
                        }
                    )

            # Apply heuristic rules
            for rule in self.heuristic_rules:
                matches = self._match_pattern(strings, rule["pattern"])
                if matches:
                    results["heuristic_matches"].append(
                        {
                            "rule": rule["name"],
                            "category": rule["category"],
                            "weight": rule["weight"],
                            "matches": len(matches),
                        }
                    )
                    results["behavioral_score"] += rule["weight"] * min(
                        len(matches) / 10, 1.0
                    )

            # Determine malware family
            results["malware_family"] = self._classify_malware_family(
                results["detected_behaviors"]
            )

            # Generate risk indicators
            results["risk_indicators"] = self._generate_risk_indicators(results)

        except Exception as e:
            self.logger.log_error(
                f"Behavioral analysis failed for {file_path}: {str(e)}"
            )

        return results

    def _extract_strings(self, file_path: str) -> List[str]:
        """Extract strings from binary file"""
        strings = []
        try:
            with open(file_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Extract ASCII strings
                    ascii_strings = re.findall(rb"[ -~]{4,}", mm)
                    strings.extend(
                        [s.decode("ascii", errors="ignore") for s in ascii_strings]
                    )

                    # Extract Unicode strings
                    unicode_strings = re.findall(rb"(?:[ -~]\x00){4,}", mm)
                    strings.extend(
                        [s.decode("utf-16le", errors="ignore") for s in unicode_strings]
                    )
        except Exception as e:
            self.logger.log_warning(f"String extraction failed: {str(e)}")

        return strings

    def _match_patterns(self, strings: List[str], patterns: List[str]) -> List[str]:
        """Match patterns against strings"""
        matches = []
        for pattern in patterns:
            for string in strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
        return matches

    def _match_pattern(self, strings: List[str], pattern: str) -> List[str]:
        """Match single pattern against strings"""
        matches = []
        for string in strings:
            if re.search(pattern, string, re.IGNORECASE):
                matches.append(string)
        return matches

    def _classify_malware_family(self, behaviors: List[Dict]) -> Optional[str]:
        """Classify malware family based on behaviors"""
        if not behaviors:
            return None

        # Simple classification based on highest confidence behavior
        best_match = max(behaviors, key=lambda x: x["confidence"])
        if best_match["confidence"] > 0.5:
            return best_match["type"]

        return None

    def _generate_risk_indicators(self, results: Dict) -> List[str]:
        """Generate human-readable risk indicators"""
        indicators = []

        if results["behavioral_score"] > 0.8:
            indicators.append("High behavioral risk score detected")

        for behavior in results["detected_behaviors"]:
            if behavior["confidence"] > 0.6:
                indicators.append(f"Strong {behavior['type']} behavior detected")

        for heuristic in results["heuristic_matches"]:
            if heuristic["weight"] > 0.7:
                indicators.append(
                    f"Suspicious {heuristic['category']} activity detected"
                )

        return indicators


class AdvancedDetector:
    """Advanced multi-layer threat detector"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = SecureLogger()
        self.behavioral_analyzer = BehavioralAnalyzer(config)
        self.yara_rules = self._load_yara_rules()
        self.file_type_handlers = self._initialize_handlers()
        self.detection_cache = {}

    def _load_yara_rules(self):
        """Load YARA rules for pattern matching"""
        try:
            rules_dir = os.path.join(os.path.dirname(__file__), "yara_rules")
            if os.path.exists(rules_dir):
                rule_files = [f for f in os.listdir(rules_dir) if f.endswith(".yar")]
                if rule_files:
                    rules_dict = {}
                    for rule_file in rule_files:
                        rules_dict[rule_file] = os.path.join(rules_dir, rule_file)
                    return yara.compile(filepaths=rules_dict)
            return None
        except Exception as e:
            self.logger.log_warning(f"Failed to load YARA rules: {str(e)}")
            return None

    def _initialize_handlers(self) -> Dict:
        """Initialize file type specific handlers"""
        return {
            "application/x-executable": self._analyze_executable,
            "application/x-dosexec": self._analyze_pe_file,
            "application/pdf": self._analyze_pdf,
            "application/zip": self._analyze_archive,
            "text/x-python": self._analyze_script,
            "text/x-shellscript": self._analyze_script,
        }

    def detect_threats(self, file_path: str) -> Dict[str, Any]:
        """Main threat detection entry point"""
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        # Check cache first
        file_hash = self._calculate_file_hash(file_path)
        if file_hash in self.detection_cache:
            cached_result = self.detection_cache[file_hash]
            if time.time() - cached_result["timestamp"] < 1800:  # 30 minutes
                return cached_result["result"]

        detection_results = {
            "file_path": file_path,
            "file_hash": file_hash,
            "file_size": os.path.getsize(file_path),
            "file_type": self._detect_file_type(file_path),
            "threats": [],
            "risk_score": 0.0,
            "analysis_details": {},
        }

        try:
            # YARA rule matching
            if self.yara_rules:
                yara_matches = self._run_yara_scan(file_path)
                if yara_matches:
                    detection_results["threats"].extend(yara_matches)

            # File type specific analysis
            file_type = detection_results["file_type"]
            if file_type in self.file_type_handlers:
                type_analysis = self.file_type_handlers[file_type](file_path)
                detection_results["analysis_details"]["type_specific"] = type_analysis
                if type_analysis.get("threats"):
                    detection_results["threats"].extend(type_analysis["threats"])

            # Behavioral analysis in sandbox
            with SandboxEnvironment(self.config) as sandbox:
                sandbox_results = sandbox.analyze_file_safely(file_path)
                detection_results["analysis_details"]["sandbox"] = sandbox_results

            # Calculate overall risk score
            detection_results["risk_score"] = self._calculate_risk_score(
                detection_results
            )

            # Cache results
            self.detection_cache[file_hash] = {
                "result": detection_results,
                "timestamp": time.time(),
            }

        except Exception as e:
            self.logger.log_error(f"Threat detection failed for {file_path}: {str(e)}")
            detection_results["error"] = str(e)

        return detection_results

    def behavioral_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform behavioral analysis"""
        return self.behavioral_analyzer.analyze_behavior(file_path)

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type using magic numbers"""
        try:
            return magic.from_file(file_path, mime=True)
        except Exception:
            # Fallback to extension-based detection
            ext = os.path.splitext(file_path)[1].lower()
            type_map = {
                ".exe": "application/x-dosexec",
                ".dll": "application/x-dosexec",
                ".pdf": "application/pdf",
                ".zip": "application/zip",
                ".py": "text/x-python",
                ".sh": "text/x-shellscript",
            }
            return type_map.get(ext, "application/octet-stream")

    def _run_yara_scan(self, file_path: str) -> List[Dict]:
        """Run YARA rules against file"""
        threats = []
        try:
            matches = self.yara_rules.match(file_path)
            for match in matches:
                threats.append(
                    {
                        "type": "yara_match",
                        "rule": match.rule,
                        "tags": match.tags,
                        "severity": "high" if "malware" in match.tags else "medium",
                        "description": f"YARA rule {match.rule} matched",
                    }
                )
        except Exception as e:
            self.logger.log_warning(f"YARA scan failed: {str(e)}")

        return threats

    def _analyze_executable(self, file_path: str) -> Dict[str, Any]:
        """Analyze executable files"""
        results = {"threats": [], "properties": {}}

        try:
            # Check for packed executables
            with open(file_path, "rb") as f:
                header = f.read(1024)
                if b"UPX" in header or b"FSG" in header:
                    results["threats"].append(
                        {
                            "type": "packed_executable",
                            "severity": "medium",
                            "description": "Executable appears to be packed",
                        }
                    )

            # Check entropy (high entropy might indicate encryption/packing)
            entropy = self._calculate_entropy(file_path)
            results["properties"]["entropy"] = entropy

            if entropy > 7.5:
                results["threats"].append(
                    {
                        "type": "high_entropy",
                        "severity": "medium",
                        "description": f"High entropy detected: {entropy:.2f}",
                    }
                )

        except Exception as e:
            self.logger.log_warning(f"Executable analysis failed: {str(e)}")

        return results

    def _analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE (Windows executable) files"""
        results = {"threats": [], "properties": {}}

        try:
            pe = pefile.PE(file_path)

            # Check for suspicious imports
            suspicious_imports = [
                "CreateRemoteThread",
                "WriteProcessMemory",
                "VirtualAllocEx",
                "SetWindowsHookEx",
                "GetAsyncKeyState",
                "CryptEncrypt",
            ]

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in suspicious_imports:
                            results["threats"].append(
                                {
                                    "type": "suspicious_import",
                                    "severity": "medium",
                                    "description": f"Suspicious API import: {imp.name.decode()}",
                                }
                            )

            # Check for unusual section characteristics
            for section in pe.sections:
                if section.Characteristics & 0x20000000:  # Executable
                    if section.Characteristics & 0x80000000:  # Writable
                        results["threats"].append(
                            {
                                "type": "rwx_section",
                                "severity": "high",
                                "description": f"Section {section.Name.decode().strip()} is readable, writable, and executable",
                            }
                        )

            pe.close()

        except Exception as e:
            self.logger.log_warning(f"PE analysis failed: {str(e)}")

        return results

    def _analyze_pdf(self, file_path: str) -> Dict[str, Any]:
        """Analyze PDF files for malicious content"""
        results = {"threats": [], "properties": {}}

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            # Check for suspicious PDF elements
            suspicious_elements = [
                b"/JavaScript",
                b"/JS",
                b"/OpenAction",
                b"/Launch",
                b"/EmbeddedFile",
                b"/XFA",
            ]

            for element in suspicious_elements:
                if element in content:
                    results["threats"].append(
                        {
                            "type": "suspicious_pdf_element",
                            "severity": "medium",
                            "description": f"Suspicious PDF element found: {element.decode()}",
                        }
                    )

        except Exception as e:
            self.logger.log_warning(f"PDF analysis failed: {str(e)}")

        return results

    def _analyze_archive(self, file_path: str) -> Dict[str, Any]:
        """Analyze archive files"""
        results = {"threats": [], "properties": {}}

        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zf:
                    # Check for zip bombs
                    total_size = sum(info.file_size for info in zf.infolist())
                    compressed_size = sum(info.compress_size for info in zf.infolist())

                    if compressed_size > 0 and total_size / compressed_size > 100:
                        results["threats"].append(
                            {
                                "type": "zip_bomb",
                                "severity": "high",
                                "description": f"Potential zip bomb detected (compression ratio: {total_size/compressed_size:.1f})",
                            }
                        )

                    # Check for suspicious file names
                    for info in zf.infolist():
                        if ".." in info.filename or info.filename.startswith("/"):
                            results["threats"].append(
                                {
                                    "type": "path_traversal",
                                    "severity": "high",
                                    "description": f"Path traversal attempt: {info.filename}",
                                }
                            )

        except Exception as e:
            self.logger.log_warning(f"Archive analysis failed: {str(e)}")

        return results

    def _analyze_script(self, file_path: str) -> Dict[str, Any]:
        """Analyze script files"""
        results = {"threats": [], "properties": {}}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check for obfuscation
            if self._is_obfuscated(content):
                results["threats"].append(
                    {
                        "type": "obfuscated_script",
                        "severity": "medium",
                        "description": "Script appears to be obfuscated",
                    }
                )

            # Check for suspicious patterns
            suspicious_patterns = [
                r"eval\s*\(",
                r"exec\s*\(",
                r"base64\.decode",
                r"urllib\.request",
                r"subprocess\.call",
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    results["threats"].append(
                        {
                            "type": "suspicious_script_pattern",
                            "severity": "medium",
                            "description": f"Suspicious pattern found: {pattern}",
                        }
                    )

        except Exception as e:
            self.logger.log_warning(f"Script analysis failed: {str(e)}")

        return results

    def _is_obfuscated(self, content: str) -> bool:
        """Check if script content appears obfuscated"""
        # Simple heuristics for obfuscation detection
        lines = content.split("\n")

        # Check for very long lines (common in obfuscated code)
        long_lines = sum(1 for line in lines if len(line) > 200)
        if long_lines > len(lines) * 0.1:
            return True

        # Check for high ratio of non-alphanumeric characters
        total_chars = len(content)
        if total_chars > 0:
            non_alnum = sum(1 for c in content if not c.isalnum() and c not in " \n\t")
            if non_alnum / total_chars > 0.6:
                return True

        return False

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if not data:
                return 0.0

            # Count byte frequencies
            byte_counts = defaultdict(int)
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts.values():
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)

            return entropy

        except Exception:
            return 0.0

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_obj = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return ""

    def _calculate_risk_score(self, detection_results: Dict) -> float:
        """Calculate overall risk score"""
        score = 0.0

        for threat in detection_results["threats"]:
            severity = threat.get("severity", "low")
            if severity == "high":
                score += 0.8
            elif severity == "medium":
                score += 0.5
            else:
                score += 0.2

        # Normalize score to 0-10 range
        return min(score, 10.0)
