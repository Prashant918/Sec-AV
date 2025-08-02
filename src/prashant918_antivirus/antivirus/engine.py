"""
Prashant918 Advanced Antivirus - Enhanced Threat Detection Engine
Multi-layered threat detection with AI/ML capabilities and cross-platform support
"""

import os
import sys
import time
import hashlib
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Core imports with error handling
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
    from ..exceptions import AntivirusError, ScanError
except ImportError:
    class AntivirusError(Exception): pass
    class ScanError(AntivirusError): pass

# Optional ML imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    tf = None

try:
    from sklearn.ensemble import IsolationForest
    import sklearn
    HAS_SKLEARN = True
    SKLEARN_VERSION = sklearn.__version__
except ImportError:
    HAS_SKLEARN = False
    IsolationForest = None
    SKLEARN_VERSION = None

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    yara = None

class ThreatLevel(Enum):
    """Threat level enumeration"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    CRITICAL = "critical"

@dataclass
class DetectionResult:
    """Detection result data structure"""
    file_path: str
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    confidence: float = 0.0
    detection_method: str = "unknown"
    threat_name: str = ""
    static_score: float = 0.0
    behavioral_score: float = 0.0
    ml_score: float = 0.0
    signature_score: float = 0.0
    heuristic_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_time: float = 0.0
    errors: List[str] = field(default_factory=list)

class HeuristicEngine:
    """Heuristic analysis engine"""
    
    def __init__(self):
        self.logger = SecureLogger("HeuristicEngine")
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js'
        }
        
    def analyze(self, file_path: str) -> float:
        """Perform heuristic analysis"""
        try:
            path = Path(file_path)
            score = 0.0
            
            # Check file extension
            if path.suffix.lower() in self.suspicious_extensions:
                score += 0.3
            
            # Check for double extensions
            if len(path.suffixes) > 1:
                score += 0.2
            
            # Check file size
            try:
                size = path.stat().st_size
                if size < 1024:  # Very small files
                    score += 0.1
                elif size > 100 * 1024 * 1024:  # Very large files
                    score += 0.1
            except OSError:
                pass
            
            # Check entropy if possible
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(8192)  # Read first 8KB
                    entropy = self._calculate_entropy(data)
                    if entropy > 7.5:  # High entropy suggests encryption/packing
                        score += 0.2
            except (OSError, PermissionError):
                pass
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed for {file_path}: {e}")
            return 0.0
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        try:
            if HAS_NUMPY:
                # Use numpy for faster calculation
                byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
                probabilities = byte_counts[byte_counts > 0] / len(data)
                entropy = -np.sum(probabilities * np.log2(probabilities))
            else:
                # Fallback calculation
                byte_counts = {}
                for byte in data:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                entropy = 0.0
                data_len = len(data)
                for count in byte_counts.values():
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0.0

class BehavioralAnalyzer:
    """Behavioral analysis engine"""
    
    def __init__(self):
        self.logger = SecureLogger("BehavioralAnalyzer")
        self.suspicious_patterns = [
            'temp', 'tmp', 'appdata', 'roaming', 'startup',
            'system32', 'syswow64', 'programdata'
        ]
        
    def analyze(self, file_path: str) -> float:
        """Perform behavioral analysis"""
        try:
            path = Path(file_path)
            score = 0.0
            
            # Check file location
            path_str = str(path).lower()
            for pattern in self.suspicious_patterns:
                if pattern in path_str:
                    score += 0.1
            
            # Check filename patterns
            filename = path.name.lower()
            if any(char in filename for char in ['$', '@', '#', '%']):
                score += 0.1
            
            # Check for hidden files
            if filename.startswith('.') and len(filename) > 1:
                score += 0.05
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            return 0.0

class MLDetector:
    """Simplified ML detector without IsolationForest issues"""
    
    def __init__(self):
        self.logger = SecureLogger("MLDetector")
        self.initialized = False
        self.models = None
        
        # Check dependencies
        if not HAS_NUMPY:
            self.logger.warning("NumPy not available - ML detection disabled")
        if not HAS_SKLEARN:
            self.logger.warning("Scikit-learn not available - ML detection disabled")
    
    def initialize(self) -> bool:
        """Initialize ML detector"""
        try:
            if not HAS_NUMPY or not HAS_SKLEARN:
                self.logger.warning("Required ML dependencies not available")
                return False
            
            self.logger.info("ML detector initialized successfully (simplified mode)")
            self.initialized = True
            return True
            
        except Exception as e:
            self.logger.error(f"ML detector initialization failed: {e}")
            return False
    
    def analyze(self, file_path: str) -> float:
        """Perform ML analysis"""
        try:
            if not self.initialized:
                return 0.0
            
            # Simple heuristic-based ML simulation
            path = Path(file_path)
            score = 0.0
            
            # File size analysis
            try:
                size = path.stat().st_size
                if size < 1024 or size > 50 * 1024 * 1024:
                    score += 0.1
            except OSError:
                pass
            
            # Extension analysis
            suspicious_exts = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js'}
            if path.suffix.lower() in suspicious_exts:
                score += 0.2
            
            # Content analysis (simplified)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(1024)  # Read first 1KB
                    if b'eval(' in data or b'exec(' in data:
                        score += 0.3
                    if data.count(b'\x00') > len(data) * 0.1:  # Many null bytes
                        score += 0.1
            except (OSError, PermissionError):
                pass
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"ML analysis failed for {file_path}: {e}")
            return 0.0

class YaraRuleManager:
    """YARA rule management"""
    
    def __init__(self):
        self.logger = SecureLogger("YaraRuleManager")
        self.rules = None
        self.rules_loaded = False
        
        if HAS_YARA:
            self._load_rules()
        else:
            self.logger.warning("YARA not available - signature detection disabled")
    
    def _load_rules(self):
        """Load YARA rules"""
        try:
            rules_dir = Path("yara_rules")
            if rules_dir.exists():
                rule_files = {}
                for rule_file in rules_dir.glob("*.yar"):
                    rule_files[rule_file.stem] = str(rule_file)
                
                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
                    self.rules_loaded = True
                    self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
                else:
                    self._create_default_rules()
            else:
                self._create_default_rules()
                
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
            self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default YARA rules"""
        try:
            default_rule = '''
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
                
                condition:
                    any of them
            }
            '''
            
            self.rules = yara.compile(source=default_rule)
            self.rules_loaded = True
            self.logger.info("Created default YARA rules")
            
        except Exception as e:
            self.logger.error(f"Failed to create default YARA rules: {e}")
    
    def scan(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        try:
            if not self.rules_loaded or not self.rules:
                return []
            
            matches = self.rules.match(file_path)
            results = []
            
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta
                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
            return []

class AdvancedThreatDetectionEngine:
    """Advanced multi-layered threat detection engine"""
    
    def __init__(self):
        self.logger = SecureLogger("ThreatEngine")
        
        # Initialize components
        self.heuristic_engine = HeuristicEngine()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.ml_detector = MLDetector()
        self.yara_manager = YaraRuleManager()
        
        # Configuration
        self.ml_threshold = secure_config.get("detection.ml_threshold", 0.85)
        self.heuristic_threshold = 0.75
        self.behavioral_threshold = 0.80
        
        # Performance optimization
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self.cache = {}
        self.cache_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'scan_time': 0.0,
            'last_scan': None
        }
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all detection components"""
        try:
            self.logger.info("Initializing advanced threat detection engine...")
            
            # Initialize ML models
            if self.ml_detector.initialize():
                self.logger.info("ML detector initialized successfully")
            else:
                self.logger.warning("ML detector initialization failed")
            
            self.logger.info("Threat detection engine initialized successfully")
            
        except Exception as e:
            self.logger.critical(f"Failed to initialize detection engine: {e}")
            raise AntivirusError(f"Engine initialization failed: {e}")
    
    def scan_file(self, file_path: str) -> DetectionResult:
        """Scan a file for threats"""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_result = self._get_cached_result(file_path)
            if cached_result:
                return cached_result
            
            result = DetectionResult(file_path=file_path)
            
            # Perform different types of analysis
            try:
                result.heuristic_score = self.heuristic_engine.analyze(file_path)
            except Exception as e:
                result.errors.append(f"Heuristic analysis failed: {e}")
            
            try:
                result.behavioral_score = self.behavioral_analyzer.analyze(file_path)
            except Exception as e:
                result.errors.append(f"Behavioral analysis failed: {e}")
            
            try:
                result.ml_score = self.ml_detector.analyze(file_path)
            except Exception as e:
                result.errors.append(f"ML analysis failed: {e}")
            
            # YARA scanning
            try:
                yara_matches = self.yara_manager.scan(file_path)
                if yara_matches:
                    result.signature_score = 1.0
                    result.threat_name = yara_matches[0].get('rule', 'YARA_Detection')
                    result.metadata['yara_matches'] = yara_matches
            except Exception as e:
                result.errors.append(f"YARA scan failed: {e}")
            
            # Calculate overall threat level
            result.threat_level, result.confidence = self._calculate_threat_level(result)
            
            # Determine detection method
            if result.signature_score > 0:
                result.detection_method = "signature"
            elif result.ml_score > self.ml_threshold:
                result.detection_method = "machine_learning"
            elif result.heuristic_score > self.heuristic_threshold:
                result.detection_method = "heuristic"
            elif result.behavioral_score > self.behavioral_threshold:
                result.detection_method = "behavioral"
            else:
                result.detection_method = "clean"
            
            result.scan_time = time.time() - start_time
            
            # Cache result
            self._cache_result(file_path, result)
            
            # Update statistics
            self._update_stats(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Scan failed for {file_path}: {e}")
            result = DetectionResult(file_path=file_path)
            result.errors.append(str(e))
            result.scan_time = time.time() - start_time
            return result
    
    def _calculate_threat_level(self, result: DetectionResult) -> Tuple[ThreatLevel, float]:
        """Calculate overall threat level and confidence"""
        try:
            # Weighted scoring
            weights = {
                'signature': 0.4,
                'ml': 0.3,
                'heuristic': 0.2,
                'behavioral': 0.1
            }
            
            total_score = (
                result.signature_score * weights['signature'] +
                result.ml_score * weights['ml'] +
                result.heuristic_score * weights['heuristic'] +
                result.behavioral_score * weights['behavioral']
            )
            
            confidence = total_score
            
            if total_score >= 0.9:
                return ThreatLevel.CRITICAL, confidence
            elif total_score >= 0.7:
                return ThreatLevel.MALWARE, confidence
            elif total_score >= 0.4:
                return ThreatLevel.SUSPICIOUS, confidence
            else:
                return ThreatLevel.CLEAN, confidence
                
        except Exception as e:
            self.logger.error(f"Threat level calculation failed: {e}")
            return ThreatLevel.CLEAN, 0.0
    
    def _get_cached_result(self, file_path: str) -> Optional[DetectionResult]:
        """Get cached scan result"""
        try:
            with self.cache_lock:
                if file_path in self.cache:
                    cached_time, result = self.cache[file_path]
                    # Cache valid for 1 hour
                    if time.time() - cached_time < 3600:
                        return result
                    else:
                        del self.cache[file_path]
            return None
        except Exception:
            return None
    
    def _cache_result(self, file_path: str, result: DetectionResult):
        """Cache scan result"""
        try:
            with self.cache_lock:
                self.cache[file_path] = (time.time(), result)
                # Limit cache size
                if len(self.cache) > 1000:
                    # Remove oldest entries
                    oldest_key = min(self.cache.keys(), 
                                   key=lambda k: self.cache[k][0])
                    del self.cache[oldest_key]
        except Exception as e:
            self.logger.debug(f"Cache operation failed: {e}")
    
    def _update_stats(self, result: DetectionResult):
        """Update scanning statistics"""
        try:
            self.stats['files_scanned'] += 1
            self.stats['scan_time'] += result.scan_time
            self.stats['last_scan'] = time.time()
            
            if result.threat_level != ThreatLevel.CLEAN:
                self.stats['threats_detected'] += 1
                
        except Exception as e:
            self.logger.debug(f"Stats update failed: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return self.stats.copy()
    
    def clear_cache(self):
        """Clear scan result cache"""
        with self.cache_lock:
            self.cache.clear()
    
    def shutdown(self):
        """Shutdown the detection engine"""
        try:
            self.thread_pool.shutdown(wait=True)
            self.clear_cache()
            self.logger.info("Threat detection engine shutdown complete")
        except Exception as e:
            self.logger.error(f"Shutdown failed: {e}")

def main():
    """Test the threat detection engine"""
    try:
        engine = AdvancedThreatDetectionEngine()
        
        # Test with a temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content for scanning")
            tmp_path = tmp.name
        
        result = engine.scan_file(tmp_path)
        print(f"Scan result: {result}")
        
        # Cleanup
        os.unlink(tmp_path)
        engine.shutdown()
        
    except Exception as e:
        print(f"Test failed: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())