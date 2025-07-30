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
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    IsolationForest = None

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
    threat_name: Optional[str] = None
    static_score: float = 0.0
    behavioral_score: float = 0.0
    ml_score: float = 0.0
    signature_score: float = 0.0
    heuristic_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_time: float = 0.0
    error: Optional[str] = None

class HeuristicEngine:
    """Heuristic analysis engine"""
    
    def __init__(self):
        self.logger = SecureLogger("HeuristicEngine")
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', 
            '.js', '.jar', '.app', '.deb', '.rpm', '.dmg'
        }
        self.packer_signatures = [
            b'UPX!', b'FSG!', b'PECompact', b'ASPack', b'Themida'
        ]
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform heuristic analysis"""
        try:
            result = {
                'score': 0.0,
                'indicators': [],
                'suspicious_features': []
            }
            
            file_path = Path(file_path)
            
            # Check file extension
            if file_path.suffix.lower() in self.suspicious_extensions:
                result['score'] += 0.3
                result['indicators'].append(f"Suspicious extension: {file_path.suffix}")
            
            # Check file size
            try:
                file_size = file_path.stat().st_size
                if file_size == 0:
                    result['score'] += 0.5
                    result['indicators'].append("Zero-byte file")
                elif file_size > 100 * 1024 * 1024:  # 100MB
                    result['score'] += 0.2
                    result['indicators'].append("Unusually large file")
            except OSError:
                pass
            
            # Check for double extensions
            if file_path.name.count('.') > 1:
                result['score'] += 0.4
                result['indicators'].append("Multiple file extensions")
            
            # Check for packer signatures
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)
                    for signature in self.packer_signatures:
                        if signature in header:
                            result['score'] += 0.6
                            result['indicators'].append(f"Packed executable detected")
                            break
            except (OSError, PermissionError):
                pass
            
            # Calculate entropy
            entropy = self._calculate_entropy(file_path)
            if entropy > 7.5:
                result['score'] += 0.4
                result['indicators'].append(f"High entropy: {entropy:.2f}")
            
            result['score'] = min(result['score'], 1.0)
            return result
            
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed for {file_path}: {e}")
            return {'score': 0.0, 'indicators': [], 'suspicious_features': []}
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB
                if not data:
                    return 0.0
                
                # Calculate byte frequency
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                # Calculate entropy
                entropy = 0.0
                data_len = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_len
                        entropy -= probability * (probability.bit_length() - 1)
                
                return entropy
        except Exception:
            return 0.0

class BehavioralAnalyzer:
    """Behavioral analysis engine"""
    
    def __init__(self):
        self.logger = SecureLogger("BehavioralAnalyzer")
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load behavioral patterns"""
        return {
            'file_operations': [
                'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile',
                'CopyFile', 'SetFileAttributes'
            ],
            'registry_operations': [
                'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
                'RegOpenKey', 'RegQueryValue'
            ],
            'network_operations': [
                'InternetOpen', 'InternetConnect', 'HttpSendRequest',
                'send', 'recv', 'connect', 'bind'
            ],
            'process_operations': [
                'CreateProcess', 'TerminateProcess', 'OpenProcess',
                'CreateRemoteThread', 'WriteProcessMemory'
            ],
            'crypto_operations': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
                'CryptAcquireContext'
            ]
        }
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform behavioral analysis"""
        try:
            result = {
                'score': 0.0,
                'behaviors': [],
                'risk_indicators': []
            }
            
            # Simulate behavioral analysis based on file characteristics
            file_path = Path(file_path)
            
            # Check for suspicious file names
            suspicious_names = [
                'svchost', 'winlogon', 'explorer', 'system32',
                'temp', 'tmp', 'cache'
            ]
            
            for name in suspicious_names:
                if name.lower() in file_path.name.lower():
                    result['score'] += 0.3
                    result['behaviors'].append(f"Suspicious filename: {name}")
            
            # Check file location
            try:
                file_str = str(file_path.absolute()).lower()
                suspicious_paths = [
                    'temp', 'tmp', 'appdata', 'downloads', 'desktop'
                ]
                
                for path in suspicious_paths:
                    if path in file_str:
                        result['score'] += 0.2
                        result['behaviors'].append(f"Suspicious location: {path}")
                        break
            except Exception:
                pass
            
            # Simulate API call analysis
            if file_path.suffix.lower() in ['.exe', '.dll', '.scr']:
                result['score'] += 0.1
                result['behaviors'].append("Executable file type")
            
            result['score'] = min(result['score'], 1.0)
            return result
            
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            return {'score': 0.0, 'behaviors': [], 'risk_indicators': []}

class MLDetector:
    """Machine Learning detector with ensemble approach"""
    
    def __init__(self):
        self.logger = SecureLogger("MLDetector")
        self.models = {}
        self.is_initialized = False
        
        if HAS_SKLEARN:
            self.anomaly_detector = IsolationForest(
                contamination=0.1, 
                random_state=42,
                n_estimators=100
            )
        else:
            self.anomaly_detector = None
        
        if HAS_TENSORFLOW:
            self.cnn_model = self._create_cnn_model()
        else:
            self.cnn_model = None
    
    def _create_cnn_model(self):
        """Create CNN model for malware detection"""
        if not HAS_TENSORFLOW:
            return None
        
        try:
            model = tf.keras.Sequential([
                tf.keras.layers.Conv1D(64, 3, activation='relu', input_shape=(1024, 1)),
                tf.keras.layers.MaxPooling1D(2),
                tf.keras.layers.Conv1D(128, 3, activation='relu'),
                tf.keras.layers.MaxPooling1D(2),
                tf.keras.layers.Conv1D(256, 3, activation='relu'),
                tf.keras.layers.GlobalMaxPooling1D(),
                tf.keras.layers.Dense(128, activation='relu'),
                tf.keras.layers.Dropout(0.5),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except Exception as e:
            self.logger.error(f"Failed to create CNN model: {e}")
            return None
    
    def initialize(self) -> bool:
        """Initialize ML models"""
        try:
            if not HAS_NUMPY:
                self.logger.warning("NumPy not available, ML detection disabled")
                return False
            
            # Train anomaly detector with synthetic data
            if self.anomaly_detector:
                synthetic_data = self._generate_synthetic_data()
                self.anomaly_detector.fit(synthetic_data)
                self.logger.info("Anomaly detector trained")
            
            self.is_initialized = True
            return True
            
        except Exception as e:
            self.logger.error(f"ML detector initialization failed: {e}")
            return False
    
    def _generate_synthetic_data(self) -> np.ndarray:
        """Generate synthetic training data"""
        if not HAS_NUMPY:
            return None
        
        # Generate 1000 samples with 10 features each
        normal_samples = np.random.normal(0, 1, (800, 10))
        anomaly_samples = np.random.normal(3, 2, (200, 10))
        
        return np.vstack([normal_samples, anomaly_samples])
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform ML analysis"""
        try:
            result = {
                'score': 0.0,
                'predictions': {},
                'features': {}
            }
            
            if not self.is_initialized:
                return result
            
            # Extract features
            features = self._extract_features(file_path)
            if not features:
                return result
            
            result['features'] = features
            
            # Anomaly detection
            if self.anomaly_detector and HAS_NUMPY:
                feature_vector = np.array([list(features.values())]).reshape(1, -1)
                anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
                is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1
                
                result['predictions']['anomaly'] = {
                    'score': float(anomaly_score),
                    'is_anomaly': bool(is_anomaly)
                }
                
                if is_anomaly:
                    result['score'] += 0.7
            
            # CNN prediction
            if self.cnn_model and HAS_TENSORFLOW and HAS_NUMPY:
                try:
                    file_data = self._prepare_file_data(file_path)
                    if file_data is not None:
                        prediction = self.cnn_model.predict(file_data, verbose=0)[0][0]
                        result['predictions']['cnn'] = float(prediction)
                        result['score'] += prediction * 0.8
                except Exception as e:
                    self.logger.debug(f"CNN prediction failed: {e}")
            
            result['score'] = min(result['score'], 1.0)
            return result
            
        except Exception as e:
            self.logger.error(f"ML analysis failed for {file_path}: {e}")
            return {'score': 0.0, 'predictions': {}, 'features': {}}
    
    def _extract_features(self, file_path: str) -> Dict[str, float]:
        """Extract features from file"""
        try:
            features = {}
            file_path = Path(file_path)
            
            # File size feature
            try:
                file_size = file_path.stat().st_size
                features['file_size'] = min(file_size / (1024 * 1024), 100)  # MB, capped at 100
            except OSError:
                features['file_size'] = 0
            
            # Entropy feature
            features['entropy'] = self._calculate_entropy(file_path)
            
            # Extension feature
            ext_map = {'.exe': 1, '.dll': 2, '.scr': 3, '.bat': 4, '.pdf': 5}
            features['extension'] = ext_map.get(file_path.suffix.lower(), 0)
            
            # String count features
            string_stats = self._analyze_strings(file_path)
            features.update(string_stats)
            
            # Pad to 10 features
            while len(features) < 10:
                features[f'padding_{len(features)}'] = 0.0
            
            return features
            
        except Exception as e:
            self.logger.debug(f"Feature extraction failed: {e}")
            return {}
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                if not data:
                    return 0.0
                
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                entropy = 0.0
                data_len = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_len
                        entropy -= probability * (probability.bit_length() - 1)
                
                return min(entropy, 8.0)
        except Exception:
            return 0.0
    
    def _analyze_strings(self, file_path: str) -> Dict[str, float]:
        """Analyze strings in file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                
            # Count printable strings
            strings = []
            current_string = ""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            if len(current_string) >= 4:
                strings.append(current_string)
            
            return {
                'string_count': min(len(strings) / 100, 10),
                'avg_string_length': min(sum(len(s) for s in strings) / max(len(strings), 1) / 10, 10),
                'suspicious_strings': sum(1 for s in strings if any(
                    keyword in s.lower() for keyword in ['password', 'admin', 'root', 'hack']
                )) / max(len(strings), 1)
            }
            
        except Exception:
            return {'string_count': 0, 'avg_string_length': 0, 'suspicious_strings': 0}
    
    def _prepare_file_data(self, file_path: str) -> Optional[np.ndarray]:
        """Prepare file data for CNN"""
        if not HAS_NUMPY:
            return None
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            
            # Pad or truncate to 1024 bytes
            if len(data) < 1024:
                data += b'\x00' * (1024 - len(data))
            else:
                data = data[:1024]
            
            # Convert to numpy array and reshape
            array = np.frombuffer(data, dtype=np.uint8)
            array = array.astype(np.float32) / 255.0
            return array.reshape(1, 1024, 1)
            
        except Exception:
            return None

class YaraRuleManager:
    """YARA rule management"""
    
    def __init__(self):
        self.logger = SecureLogger("YaraRuleManager")
        self.rules = None
        self.rules_loaded = False
        
        if HAS_YARA:
            self._load_rules()
    
    def _load_rules(self):
        """Load YARA rules"""
        try:
            rules_dir = Path("yara_rules")
            if not rules_dir.exists():
                rules_dir.mkdir(parents=True, exist_ok=True)
                self._create_default_rules(rules_dir)
            
            rule_files = {}
            for rule_file in rules_dir.glob("*.yar"):
                rule_files[rule_file.stem] = str(rule_file)
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                self.rules_loaded = True
                self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
            else:
                self.logger.warning("No YARA rules found")
                
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
    
    def _create_default_rules(self, rules_dir: Path):
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
            rule_path = rules_dir / filename
            with open(rule_path, 'w') as f:
                f.write(content)
    
    def scan(self, file_path: str) -> Dict[str, Any]:
        """Scan file with YARA rules"""
        try:
            result = {
                'score': 0.0,
                'matches': [],
                'rule_count': 0
            }
            
            if not HAS_YARA or not self.rules_loaded:
                return result
            
            matches = self.rules.match(file_path)
            result['rule_count'] = len(matches)
            
            for match in matches:
                result['matches'].append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                })
                
                # Calculate score based on rule matches
                if 'malware' in match.rule.lower():
                    result['score'] += 0.8
                elif 'suspicious' in match.rule.lower():
                    result['score'] += 0.6
                else:
                    result['score'] += 0.4
            
            result['score'] = min(result['score'], 1.0)
            return result
            
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
            return {'score': 0.0, 'matches': [], 'rule_count': 0}

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
    
    def scan_file(self, file_path: str, use_cache: bool = True) -> DetectionResult:
        """Scan a single file for threats"""
        start_time = time.time()
        
        try:
            file_path = str(Path(file_path).resolve())
            
            # Check cache
            if use_cache:
                cached_result = self._get_cached_result(file_path)
                if cached_result:
                    return cached_result
            
            # Validate file
            if not Path(file_path).exists():
                return DetectionResult(
                    file_path=file_path,
                    error="File not found"
                )
            
            # Perform multi-layered analysis
            result = DetectionResult(file_path=file_path)
            
            # Run all analysis methods
            analyses = [
                ('heuristic', self.heuristic_engine.analyze),
                ('behavioral', self.behavioral_analyzer.analyze),
                ('ml', self.ml_detector.analyze),
                ('yara', self.yara_manager.scan)
            ]
            
            for analysis_name, analysis_func in analyses:
                try:
                    analysis_result = analysis_func(file_path)
                    score = analysis_result.get('score', 0.0)
                    
                    if analysis_name == 'heuristic':
                        result.heuristic_score = score
                        result.metadata['heuristic'] = analysis_result
                    elif analysis_name == 'behavioral':
                        result.behavioral_score = score
                        result.metadata['behavioral'] = analysis_result
                    elif analysis_name == 'ml':
                        result.ml_score = score
                        result.metadata['ml'] = analysis_result
                    elif analysis_name == 'yara':
                        result.signature_score = score
                        result.metadata['yara'] = analysis_result
                        
                except Exception as e:
                    self.logger.error(f"{analysis_name} analysis failed: {e}")
            
            # Calculate overall threat assessment
            result = self._calculate_threat_level(result)
            
            # Update statistics
            result.scan_time = time.time() - start_time
            self._update_stats(result)
            
            # Cache result
            if use_cache:
                self._cache_result(file_path, result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Scan failed for {file_path}: {e}")
            return DetectionResult(
                file_path=file_path,
                error=str(e),
                scan_time=time.time() - start_time
            )
    
    def _calculate_threat_level(self, result: DetectionResult) -> DetectionResult:
        """Calculate overall threat level"""
        try:
            # Weighted scoring
            weights = {
                'heuristic': 0.2,
                'behavioral': 0.25,
                'ml': 0.35,
                'signature': 0.2
            }
            
            overall_score = (
                result.heuristic_score * weights['heuristic'] +
                result.behavioral_score * weights['behavioral'] +
                result.ml_score * weights['ml'] +
                result.signature_score * weights['signature']
            )
            
            result.confidence = overall_score
            
            # Determine threat level
            if overall_score >= 0.9:
                result.threat_level = ThreatLevel.CRITICAL
                result.threat_name = "High-confidence malware"
                result.detection_method = "Multi-layer analysis"
            elif overall_score >= 0.7:
                result.threat_level = ThreatLevel.MALWARE
                result.threat_name = "Probable malware"
                result.detection_method = "Statistical analysis"
            elif overall_score >= 0.4:
                result.threat_level = ThreatLevel.SUSPICIOUS
                result.threat_name = "Suspicious file"
                result.detection_method = "Heuristic analysis"
            else:
                result.threat_level = ThreatLevel.CLEAN
                result.threat_name = None
                result.detection_method = "Clean"
            
            return result
            
        except Exception as e:
            self.logger.error(f"Threat level calculation failed: {e}")
            result.error = str(e)
            return result
    
    def _get_cached_result(self, file_path: str) -> Optional[DetectionResult]:
        """Get cached scan result"""
        try:
            with self.cache_lock:
                if file_path in self.cache:
                    cached_data = self.cache[file_path]
                    # Check if cache is still valid (1 hour)
                    if time.time() - cached_data['timestamp'] < 3600:
                        return cached_data['result']
                    else:
                        del self.cache[file_path]
            return None
        except Exception:
            return None
    
    def _cache_result(self, file_path: str, result: DetectionResult):
        """Cache scan result"""
        try:
            with self.cache_lock:
                self.cache[file_path] = {
                    'result': result,
                    'timestamp': time.time()
                }
                
                # Limit cache size
                if len(self.cache) > 1000:
                    oldest_key = min(self.cache.keys(), 
                                   key=lambda k: self.cache[k]['timestamp'])
                    del self.cache[oldest_key]
        except Exception:
            pass
    
    def _update_stats(self, result: DetectionResult):
        """Update scanning statistics"""
        try:
            self.stats['files_scanned'] += 1
            self.stats['scan_time'] += result.scan_time
            self.stats['last_scan'] = time.time()
            
            if result.threat_level in [ThreatLevel.MALWARE, ThreatLevel.CRITICAL]:
                self.stats['threats_detected'] += 1
                
        except Exception:
            pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return self.stats.copy()
    
    def clear_cache(self):
        """Clear scan cache"""
        with self.cache_lock:
            self.cache.clear()
    
    def shutdown(self):
        """Shutdown the engine"""
        try:
            self.thread_pool.shutdown(wait=True)
            self.clear_cache()
            self.logger.info("Threat detection engine shutdown complete")
        except Exception as e:
            self.logger.error(f"Engine shutdown error: {e}")

# Compatibility aliases for backward compatibility
EnsembleMLDetector = MLDetector
