import asyncio
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import hashlib
import time
import logging
import os
import struct
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

# Try to import optional dependencies
try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

class ThreatLevel(Enum):
    CLEAN = 0
    SUSPICIOUS = 1
    MALWARE = 2
    CRITICAL = 3

@dataclass
class DetectionResult:
    file_path: str
    threat_level: ThreatLevel
    confidence: float
    detection_method: str
    threat_name: Optional[str] = None
    behavioral_score: float = 0.0
    static_score: float = 0.0
    ml_score: float = 0.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class AdvancedDetectionEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize ML models
        self.cnn_model = None
        self.behavioral_model = None
        self.anomaly_detector = None
        
        # Initialize YARA rules
        self.yara_rules = None
        
        # Thread pools for parallel processing
        max_threads = config.get('max_threads', min(8, os.cpu_count() or 1))
        max_processes = config.get('max_processes', min(4, os.cpu_count() or 1))
        
        self.thread_pool = ThreadPoolExecutor(max_workers=max_threads)
        self.process_pool = ProcessPoolExecutor(max_workers=max_processes)
        
        # Detection statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'scan_time': 0.0
        }
        
        # Initialize components
        self._initialize_models()
        self._load_yara_rules()
    
    def _initialize_models(self):
        """Initialize machine learning models"""
        try:
            if HAS_SKLEARN:
                self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
                self.logger.info("Anomaly detector initialized")
            
            if HAS_TENSORFLOW:
                self._initialize_cnn_model()
            else:
                self.logger.warning("TensorFlow not available, ML detection disabled")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
    
    def _initialize_cnn_model(self):
        """Initialize CNN model for malware detection"""
        try:
            # Create a simple CNN model
            self.cnn_model = tf.keras.Sequential([
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
            
            self.cnn_model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Try to load pre-trained weights
            weights_path = self.config.get('cnn_weights_path', 'models/cnn_malware_detector.h5')
            if os.path.exists(weights_path):
                self.cnn_model.load_weights(weights_path)
                self.logger.info("CNN model weights loaded")
            else:
                self.logger.warning("Pre-trained CNN weights not found")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize CNN model: {e}")
            self.cnn_model = None
    
    def _load_yara_rules(self):
        """Load YARA rules for signature-based detection"""
        try:
            if not HAS_YARA:
                self.logger.warning("YARA not available, signature detection disabled")
                return
            
            rules_path = self.config.get('yara_rules_path', 'rules/malware.yar')
            if os.path.exists(rules_path):
                self.yara_rules = yara.compile(filepath=rules_path)
                self.logger.info("YARA rules loaded")
            else:
                # Create basic rules if file doesn't exist
                self._create_basic_yara_rules()
                
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
    
    def _create_basic_yara_rules(self):
        """Create basic YARA rules if none exist"""
        try:
            basic_rules = '''
            rule Suspicious_Executable {
                meta:
                    description = "Detects suspicious executable patterns"
                strings:
                    $mz = { 4D 5A }
                    $pe = "PE"
                    $suspicious1 = "cmd.exe" nocase
                    $suspicious2 = "powershell" nocase
                    $suspicious3 = "rundll32" nocase
                condition:
                    $mz at 0 and $pe and any of ($suspicious*)
            }
            
            rule Potential_Malware {
                meta:
                    description = "Detects potential malware indicators"
                strings:
                    $encrypt1 = "encrypt" nocase
                    $encrypt2 = "decrypt" nocase
                    $ransom1 = "ransom" nocase
                    $ransom2 = "bitcoin" nocase
                condition:
                    any of them
            }
            '''
            
            self.yara_rules = yara.compile(source=basic_rules)
            self.logger.info("Basic YARA rules created")
            
        except Exception as e:
            self.logger.error(f"Failed to create basic YARA rules: {e}")
    
    async def scan_file_advanced(self, file_path: str) -> DetectionResult:
        """Advanced file scanning with multiple detection methods"""
        start_time = time.time()
        
        try:
            # Validate file exists and is accessible
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"Cannot read file: {file_path}")
            
            # Run multiple detection methods in parallel
            tasks = [
                self._static_analysis(file_path),
                self._behavioral_analysis(file_path),
                self._ml_detection(file_path),
                self._signature_detection(file_path),
                self._heuristic_analysis(file_path)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            detection_result = self._combine_detection_results(file_path, results)
            
            # Update statistics
            scan_time = time.time() - start_time
            self.stats['files_scanned'] += 1
            self.stats['scan_time'] += scan_time
            
            if detection_result.threat_level != ThreatLevel.CLEAN:
                self.stats['threats_detected'] += 1
            
            return detection_result
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return DetectionResult(
                file_path=file_path,
                threat_level=ThreatLevel.CLEAN,
                confidence=0.0,
                detection_method="error",
                metadata={'error': str(e)}
            )
    
    async def _static_analysis(self, file_path: str) -> Tuple[float, Dict]:
        """Perform static analysis on the file"""
        try:
            # Read file data with size limit
            max_read_size = self.config.get('max_read_size', 10240)  # 10KB default
            
            with open(file_path, 'rb') as f:
                file_data = f.read(max_read_size)
            
            # Get file stats
            file_stats = os.stat(file_path)
            
            # Extract static features
            features = {
                'file_size': file_stats.st_size,
                'entropy': self._calculate_entropy(file_data),
                'pe_features': self._extract_pe_features(file_data),
                'string_features': self._extract_string_features(file_data),
                'file_extension': os.path.splitext(file_path)[1].lower()
            }
            
            # Calculate static score based on features
            static_score = self._calculate_static_score(features)
            
            return static_score, features
            
        except Exception as e:
            self.logger.error(f"Static analysis failed for {file_path}: {e}")
            return 0.0, {'error': str(e)}
    
    async def _behavioral_analysis(self, file_path: str) -> Tuple[float, Dict]:
        """Perform behavioral analysis (simulated for now)"""
        try:
            # In a real implementation, this would involve:
            # - Running the file in a sandbox
            # - Monitoring system calls
            # - Analyzing network activity
            # - Checking registry modifications
            
            # For now, simulate based on file characteristics
            behavioral_indicators = {
                'network_connections': 0,
                'file_modifications': 0,
                'registry_changes': 0,
                'process_injections': 0,
                'suspicious_apis': []
            }
            
            # Simple heuristics based on file type and name
            file_name = os.path.basename(file_path).lower()
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Check for suspicious file names
            suspicious_names = ['svchost', 'winlogon', 'explorer', 'lsass']
            if any(name in file_name for name in suspicious_names) and file_ext == '.exe':
                behavioral_indicators['suspicious_apis'].append('process_masquerading')
            
            # Simulate behavioral scoring
            behavioral_score = self._calculate_behavioral_score(behavioral_indicators)
            
            return behavioral_score, behavioral_indicators
            
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            return 0.0, {'error': str(e)}
    
    async def _ml_detection(self, file_path: str) -> Tuple[float, Dict]:
        """Machine learning based detection"""
        try:
            if not self.cnn_model:
                return 0.0, {'error': 'ML model not available'}
            
            # Prepare file data for ML model
            with open(file_path, 'rb') as f:
                file_data = f.read(1024)  # Read first 1KB
            
            # Pad or truncate to fixed size
            if len(file_data) < 1024:
                file_data += b'\x00' * (1024 - len(file_data))
            else:
                file_data = file_data[:1024]
            
            # Convert to numpy array
            data_array = np.frombuffer(file_data, dtype=np.uint8)
            data_array = data_array.reshape(1, 1024, 1).astype(np.float32) / 255.0
            
            # Get prediction
            prediction = self.cnn_model.predict(data_array, verbose=0)[0][0]
            
            ml_features = {
                'cnn_prediction': float(prediction),
                'model_confidence': float(abs(prediction - 0.5) * 2)
            }
            
            return float(prediction), ml_features
            
        except Exception as e:
            self.logger.error(f"ML detection failed for {file_path}: {e}")
            return 0.0, {'error': str(e)}
    
    async def _signature_detection(self, file_path: str) -> Tuple[float, Dict]:
        """YARA-based signature detection"""
        try:
            if not self.yara_rules:
                return 0.0, {'error': 'YARA rules not available'}
            
            matches = self.yara_rules.match(file_path)
            
            signature_features = {
                'yara_matches': [match.rule for match in matches],
                'match_count': len(matches)
            }
            
            # Calculate signature score
            signature_score = min(len(matches) * 0.3, 1.0)
            
            return signature_score, signature_features
            
        except Exception as e:
            self.logger.error(f"Signature detection failed for {file_path}: {e}")
            return 0.0, {'error': str(e)}
    
    async def _heuristic_analysis(self, file_path: str) -> Tuple[float, Dict]:
        """Heuristic-based analysis"""
        try:
            heuristic_score = 0.0
            heuristic_features = {}
            
            # File extension analysis
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in suspicious_extensions:
                heuristic_score += 0.2
                heuristic_features['suspicious_extension'] = True
            
            # File size analysis
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1024:  # Very small executable
                    heuristic_score += 0.3
                    heuristic_features['suspicious_size'] = True
                elif file_size > 100 * 1024 * 1024:  # Very large file (>100MB)
                    heuristic_score += 0.1
                    heuristic_features['large_file'] = True
            except OSError:
                pass
            
            # Packer detection (simplified)
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)
                    
                # Check for common packer signatures
                packer_signatures = [b'UPX', b'FSG', b'PECompact', b'ASPack']
                for sig in packer_signatures:
                    if sig in header:
                        heuristic_score += 0.4
                        heuristic_features['packed'] = True
                        heuristic_features['packer'] = sig.decode('ascii', errors='ignore')
                        break
            except (OSError, IOError):
                pass
            
            # Check for double extensions
            file_name = os.path.basename(file_path)
            if file_name.count('.') > 1:
                heuristic_score += 0.3
                heuristic_features['double_extension'] = True
            
            return min(heuristic_score, 1.0), heuristic_features
            
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed for {file_path}: {e}")
            return 0.0, {'error': str(e)}
    
    def _combine_detection_results(self, file_path: str, results: List) -> DetectionResult:
        """Combine results from all detection methods"""
        # Extract results with error handling
        static_score, static_features = self._extract_result(results[0])
        behavioral_score, behavioral_features = self._extract_result(results[1])
        ml_score, ml_features = self._extract_result(results[2])
        signature_score, signature_features = self._extract_result(results[3])
        heuristic_score, heuristic_features = self._extract_result(results[4])
        
        # Weighted combination of scores
        weights = self.config.get('detection_weights', {
            'static': 0.2,
            'behavioral': 0.3,
            'ml': 0.25,
            'signature': 0.15,
            'heuristic': 0.1
        })
        
        combined_score = (
            static_score * weights['static'] +
            behavioral_score * weights['behavioral'] +
            ml_score * weights['ml'] +
            signature_score * weights['signature'] +
            heuristic_score * weights['heuristic']
        )
        
        # Determine threat level based on thresholds
        thresholds = self.config.get('threat_thresholds', {
            'critical': 0.8,
            'malware': 0.6,
            'suspicious': 0.3
        })
        
        if combined_score >= thresholds['critical']:
            threat_level = ThreatLevel.CRITICAL
        elif combined_score >= thresholds['malware']:
            threat_level = ThreatLevel.MALWARE
        elif combined_score >= thresholds['suspicious']:
            threat_level = ThreatLevel.SUSPICIOUS
        else:
            threat_level = ThreatLevel.CLEAN
        
        # Determine detection method
        detection_methods = []
        method_threshold = 0.5
        
        if signature_score > method_threshold:
            detection_methods.append("signature")
        if ml_score > method_threshold:
            detection_methods.append("ml")
        if behavioral_score > method_threshold:
            detection_methods.append("behavioral")
        if heuristic_score > method_threshold:
            detection_methods.append("heuristic")
        if static_score > method_threshold:
            detection_methods.append("static")
        
        detection_method = "+".join(detection_methods) if detection_methods else "clean"
        
        # Determine threat name
        threat_name = None
        if signature_features.get('yara_matches'):
            threat_name = signature_features['yara_matches'][0]
        elif threat_level != ThreatLevel.CLEAN:
            threat_name = f"Generic.{threat_level.name}"
        
        # Combine metadata
        metadata = {
            'static_features': static_features,
            'behavioral_features': behavioral_features,
            'ml_features': ml_features,
            'signature_features': signature_features,
            'heuristic_features': heuristic_features,
            'individual_scores': {
                'static': static_score,
                'behavioral': behavioral_score,
                'ml': ml_score,
                'signature': signature_score,
                'heuristic': heuristic_score
            }
        }
        
        return DetectionResult(
            file_path=file_path,
            threat_level=threat_level,
            confidence=combined_score,
            detection_method=detection_method,
            threat_name=threat_name,
            behavioral_score=behavioral_score,
            static_score=static_score,
            ml_score=ml_score,
            metadata=metadata
        )
    
    def _extract_result(self, result) -> Tuple[float, Dict]:
        """Extract result from detection method, handling exceptions"""
        if isinstance(result, Exception):
            return 0.0, {'error': str(result)}
        elif isinstance(result, tuple) and len(result) == 2:
            return result
        else:
            return 0.0, {'error': 'Invalid result format'}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _extract_pe_features(self, data: bytes) -> Dict:
        """Extract PE file features (simplified)"""
        features = {
            'is_pe': False,
            'sections': 0,
            'imports': 0,
            'exports': 0,
            'has_dos_header': False,
            'has_pe_signature': False
        }
        
        try:
            # Check for DOS header (MZ signature)
            if len(data) >= 2 and data[:2] == b'MZ':
                features['has_dos_header'] = True
                
                # Check for PE signature
                if len(data) >= 64:
                    # Get PE header offset from DOS header
                    pe_offset = struct.unpack('<I', data[60:64])[0]
                    if pe_offset < len(data) - 4:
                        pe_signature = data[pe_offset:pe_offset+4]
                        if pe_signature == b'PE\x00\x00':
                            features['is_pe'] = True
                            features['has_pe_signature'] = True
                            
                            # Try to extract more PE information
                            if len(data) >= pe_offset + 24:
                                # Number of sections is at offset 6 from PE signature
                                sections_offset = pe_offset + 6
                                if sections_offset + 2 <= len(data):
                                    features['sections'] = struct.unpack('<H', data[sections_offset:sections_offset+2])[0]
        
        except (struct.error, IndexError):
            pass
        
        return features
    
    def _extract_string_features(self, data: bytes) -> Dict:
        """Extract string-based features"""
        try:
            # Extract printable strings
            strings = []
            current_string = ""
            min_string_length = 4
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_string_length:
                        strings.append(current_string)
                    current_string = ""
            
            # Add final string if exists
            if len(current_string) >= min_string_length:
                strings.append(current_string)
            
            # Analyze strings for suspicious patterns
            suspicious_patterns = [
                'cmd.exe', 'powershell', 'regedit', 'taskkill',
                'bitcoin', 'cryptocurrency', 'ransom', 'encrypt',
                'decrypt', 'payload', 'shellcode', 'backdoor'
            ]
            
            suspicious_strings = []
            for string in strings:
                for pattern in suspicious_patterns:
                    if pattern.lower() in string.lower():
                        suspicious_strings.append(string)
                        break
            
            # Calculate average string length
            avg_length = np.mean([len(s) for s in strings]) if strings else 0
            
            return {
                'total_strings': len(strings),
                'suspicious_strings': len(suspicious_strings),
                'avg_string_length': float(avg_length),
                'suspicious_string_samples': suspicious_strings[:5]  # First 5 samples
            }
            
        except Exception as e:
            self.logger.debug(f"Error extracting string features: {e}")
            return {
                'total_strings': 0,
                'suspicious_strings': 0,
                'avg_string_length': 0.0,
                'error': str(e)
            }
    
    def _calculate_static_score(self, features: Dict) -> float:
        """Calculate static analysis score"""
        score = 0.0
        
        try:
            # High entropy indicates packing/encryption
            entropy = features.get('entropy', 0)
            if entropy > 7.5:
                score += 0.3
            elif entropy > 6.5:
                score += 0.1
            
            # PE file analysis
            pe_features = features.get('pe_features', {})
            if pe_features.get('is_pe'):
                sections = pe_features.get('sections', 0)
                if sections > 10:  # Unusual number of sections
                    score += 0.2
                elif sections == 0:  # No sections (suspicious)
                    score += 0.3
            
            # String analysis
            string_features = features.get('string_features', {})
            suspicious_strings = string_features.get('suspicious_strings', 0)
            total_strings = string_features.get('total_strings', 1)
            
            if suspicious_strings > 0:
                suspicious_ratio = suspicious_strings / total_strings
                score += min(suspicious_ratio * 0.5, 0.4)
            
            # File extension check
            file_ext = features.get('file_extension', '')
            if file_ext in ['.exe', '.scr', '.bat', '.cmd']:
                score += 0.1
            
        except Exception as e:
            self.logger.debug(f"Error calculating static score: {e}")
        
        return min(score, 1.0)
    
    def _calculate_behavioral_score(self, indicators: Dict) -> float:
        """Calculate behavioral analysis score"""
        score = 0.0
        
        try:
            # Network activity
            network_connections = indicators.get('network_connections', 0)
            if network_connections > 5:
                score += 0.3
            
            # File modifications
            file_modifications = indicators.get('file_modifications', 0)
            if file_modifications > 10:
                score += 0.2
            
            # Registry changes
            registry_changes = indicators.get('registry_changes', 0)
            if registry_changes > 5:
                score += 0.2
            
            # Process injections
            process_injections = indicators.get('process_injections', 0)
            if process_injections > 0:
                score += 0.5
            
            # Suspicious APIs
            suspicious_apis = indicators.get('suspicious_apis', [])
            if suspicious_apis:
                score += min(len(suspicious_apis) * 0.1, 0.3)
            
        except Exception as e:
            self.logger.debug(f"Error calculating behavioral score: {e}")
        
        return min(score, 1.0)
    
    def get_statistics(self) -> Dict:
        """Get detection engine statistics"""
        stats = self.stats.copy()
        if stats['files_scanned'] > 0:
            stats['avg_scan_time'] = stats['scan_time'] / stats['files_scanned']
            stats['detection_rate'] = stats['threats_detected'] / stats['files_scanned']
        else:
            stats['avg_scan_time'] = 0.0
            stats['detection_rate'] = 0.0
        
        # Add component availability
        stats['components'] = {
            'tensorflow': HAS_TENSORFLOW,
            'sklearn': HAS_SKLEARN,
            'yara': HAS_YARA,
            'cnn_model': self.cnn_model is not None,
            'yara_rules': self.yara_rules is not None
        }
        
        return stats
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            self.thread_pool.shutdown(wait=True)
            self.process_pool.shutdown(wait=True)
            self.logger.info("Detection engine cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")