"""
Advanced Signature Manager - YARA rules and hash-based detection
"""
import os
import hashlib
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

try:
    from ..database.manager import db_manager
except ImportError:
    db_manager = None

try:
    from ..exceptions import SignatureError, DatabaseError
except ImportError:
    class SignatureError(Exception):
        pass
    class DatabaseError(Exception):
        pass

# Optional YARA support
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    yara = None

class YaraRuleManager:
    """
    YARA rule management and scanning
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        self.logger = SecureLogger("YaraRuleManager")
        self.rules_dir = Path(rules_dir) if rules_dir else Path("yara_rules")
        self.compiled_rules = None
        self.rules_loaded = False
        
        if HAS_YARA:
            self._initialize_rules()
        else:
            self.logger.warning("YARA not available - signature detection disabled")
    
    def _initialize_rules(self):
        """Initialize YARA rules"""
        try:
            # Create rules directory if it doesn't exist
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            
            # Create default rules if none exist
            if not any(self.rules_dir.glob("*.yar")):
                self._create_default_rules()
            
            # Compile rules
            self._compile_rules()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize YARA rules: {e}")
    
    def _create_default_rules(self):
        """Create default YARA rules"""
        default_rules = {
            "malware_generic.yar": '''
rule Generic_Malware_Strings
{
    meta:
        description = "Generic malware string patterns"
        author = "Advanced Antivirus"
    
    strings:
        $s1 = "backdoor" nocase
        $s2 = "keylogger" nocase
        $s3 = "trojan" nocase
        $s4 = "rootkit" nocase
        $s5 = "ransomware" nocase
        $s6 = "payload" nocase
        $s7 = "shellcode" nocase
    
    condition:
        any of them
}

rule Suspicious_API_Calls
{
    meta:
        description = "Suspicious Windows API calls"
    
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "SetWindowsHookEx"
        $api5 = "GetAsyncKeyState"
    
    condition:
        3 of them
}
''',
            "ransomware.yar": '''
rule Ransomware_Indicators
{
    meta:
        description = "Ransomware behavior indicators"
    
    strings:
        $r1 = "encrypt" nocase
        $r2 = "decrypt" nocase
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = ".locked"
        $r6 = ".encrypted"
    
    condition:
        2 of them
}
'''
        }
        
        for filename, content in default_rules.items():
            rule_path = self.rules_dir / filename
            with open(rule_path, 'w') as f:
                f.write(content)
            
            self.logger.info(f"Created default rule: {filename}")
    
    def _compile_rules(self):
        """Compile YARA rules"""
        try:
            rule_files = list(self.rules_dir.glob("*.yar"))
            
            if not rule_files:
                self.logger.warning("No YARA rule files found")
                return
            
            # Create rules dictionary
            rules_dict = {}
            for rule_file in rule_files:
                rule_name = rule_file.stem
                rules_dict[rule_name] = str(rule_file)
            
            # Compile rules
            self.compiled_rules = yara.compile(filepaths=rules_dict)
            self.rules_loaded = True
            
            self.logger.info(f"Compiled {len(rule_files)} YARA rule files")
            
        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            self.rules_loaded = False
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        if not HAS_YARA or not self.rules_loaded:
            return []
        
        try:
            matches = self.compiled_rules.match(file_path)
            
            results = []
            for match in matches:
                result = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                # Add string matches
                for string_match in match.strings:
                    result['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'matched_data': instance.matched_data.decode('utf-8', errors='ignore')[:100]
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                results.append(result)
            
            return results
            
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
            return []

class AdvancedSignatureManager:
    """
    Advanced signature management system
    """
    
    def __init__(self):
        self.logger = SecureLogger("SignatureManager")
        self.yara_manager = YaraRuleManager() if HAS_YARA else None
        self.hash_signatures = set()
        self.pattern_signatures = []
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'signatures_loaded': 0,
            'scans_performed': 0,
            'threats_detected': 0,
            'last_update': None
        }
        
        # Initialize signatures
        self._load_signatures()
    
    def _load_signatures(self):
        """Load signatures from database and files"""
        try:
            # Load hash signatures
            self._load_hash_signatures()
            
            # Load pattern signatures
            self._load_pattern_signatures()
            
            self.logger.info(f"Loaded {len(self.hash_signatures)} hash signatures")
            
        except Exception as e:
            self.logger.error(f"Failed to load signatures: {e}")
    
    def _load_hash_signatures(self):
        """Load hash signatures from database"""
        if not db_manager:
            # Load from default set if no database
            default_hashes = {
                # Example malware hashes (these are fake for demonstration)
                "d41d8cd98f00b204e9800998ecf8427e",  # Empty file MD5
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # Empty file SHA1
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty file SHA256
            }
            self.hash_signatures.update(default_hashes)
            return
        
        try:
            # Query database for hash signatures
            query = "SELECT file_hash FROM hash_signatures WHERE severity IN ('high', 'critical')"
            results = db_manager.execute_query(query)
            
            for result in results:
                self.hash_signatures.add(result['file_hash'])
            
        except Exception as e:
            self.logger.error(f"Failed to load hash signatures from database: {e}")
    
    def _load_pattern_signatures(self):
        """Load pattern signatures"""
        # Default pattern signatures
        self.pattern_signatures = [
            {
                'name': 'Suspicious_Strings',
                'patterns': [b'backdoor', b'keylogger', b'trojan', b'rootkit'],
                'severity': 'medium'
            },
            {
                'name': 'Crypto_Patterns',
                'patterns': [b'bitcoin', b'ransom', b'decrypt', b'encrypt'],
                'severity': 'high'
            }
        ]
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file scanning"""
        scan_start = time.time()
        
        results = {
            'file_path': file_path,
            'scan_time': 0.0,
            'threats_detected': [],
            'hash_matches': [],
            'pattern_matches': [],
            'yara_matches': [],
            'risk_level': 'clean',
            'confidence': 0.0
        }
        
        try:
            # Calculate file hashes
            file_hashes = self._calculate_file_hashes(file_path)
            
            # Check hash signatures
            hash_matches = self._check_hash_signatures(file_hashes)
            results['hash_matches'] = hash_matches
            
            # Check pattern signatures
            pattern_matches = self._check_pattern_signatures(file_path)
            results['pattern_matches'] = pattern_matches
            
            # Check YARA rules
            if self.yara_manager:
                yara_matches = self.yara_manager.scan_file(file_path)
                results['yara_matches'] = yara_matches
            
            # Calculate overall risk
            results['risk_level'], results['confidence'] = self._calculate_risk_level(
                hash_matches, pattern_matches, results['yara_matches']
            )
            
            # Update statistics
            with self.lock:
                self.stats['scans_performed'] += 1
                if results['risk_level'] != 'clean':
                    self.stats['threats_detected'] += 1
            
        except Exception as e:
            self.logger.error(f"Signature scan failed for {file_path}: {e}")
            results['error'] = str(e)
        
        results['scan_time'] = time.time() - scan_start
        return results
    
    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            self.logger.error(f"Failed to calculate hashes for {file_path}: {e}")
        
        return hashes
    
    def _check_hash_signatures(self, file_hashes: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check file hashes against signature database"""
        matches = []
        
        for hash_type, hash_value in file_hashes.items():
            if hash_value in self.hash_signatures:
                matches.append({
                    'hash_type': hash_type,
                    'hash_value': hash_value,
                    'threat_name': 'Known_Malware',
                    'severity': 'high'
                })
        
        return matches
    
    def _check_pattern_signatures(self, file_path: str) -> List[Dict[str, Any]]:
        """Check file content against pattern signatures"""
        matches = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read first 1MB for pattern matching
                data = f.read(1024 * 1024)
            
            for signature in self.pattern_signatures:
                for pattern in signature['patterns']:
                    if pattern in data:
                        matches.append({
                            'signature_name': signature['name'],
                            'pattern': pattern.decode('utf-8', errors='ignore'),
                            'severity': signature['severity']
                        })
                        break  # Only count once per signature
        
        except Exception as e:
            self.logger.error(f"Pattern matching failed for {file_path}: {e}")
        
        return matches
    
    def _calculate_risk_level(self, hash_matches: List, pattern_matches: List, 
                            yara_matches: List) -> Tuple[str, float]:
        """Calculate overall risk level and confidence"""
        score = 0.0
        
        # Hash matches are high confidence
        if hash_matches:
            score += 0.9
        
        # Pattern matches
        for match in pattern_matches:
            if match['severity'] == 'high':
                score += 0.6
            elif match['severity'] == 'medium':
                score += 0.4
            else:
                score += 0.2
        
        # YARA matches
        if yara_matches:
            score += 0.7
        
        # Determine risk level
        if score >= 0.8:
            return 'critical', min(score, 1.0)
        elif score >= 0.6:
            return 'high', score
        elif score >= 0.3:
            return 'medium', score
        elif score > 0:
            return 'low', score
        else:
            return 'clean', 0.0
    
    def add_hash_signature(self, file_hash: str, hash_type: str, 
                          threat_name: str, severity: str) -> bool:
        """Add new hash signature"""
        try:
            with self.lock:
                self.hash_signatures.add(file_hash)
            
            # Add to database if available
            if db_manager:
                db_manager.insert_hash_signature(file_hash, hash_type, threat_name, severity)
            
            self.logger.info(f"Added hash signature: {file_hash}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add hash signature: {e}")
            return False
    
    def update_signatures(self) -> bool:
        """Update signatures from external sources"""
        try:
            self.logger.info("Updating signatures...")
            
            # Reload signatures
            self._load_signatures()
            
            # Update statistics
            with self.lock:
                self.stats['last_update'] = time.time()
                self.stats['signatures_loaded'] = len(self.hash_signatures)
            
            self.logger.info("Signature update completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Signature update failed: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get signature manager statistics"""
        with self.lock:
            stats = self.stats.copy()
        
        stats.update({
            'hash_signatures_count': len(self.hash_signatures),
            'pattern_signatures_count': len(self.pattern_signatures),
            'yara_rules_loaded': self.yara_manager.rules_loaded if self.yara_manager else False,
            'yara_available': HAS_YARA
        })
        
        return stats
