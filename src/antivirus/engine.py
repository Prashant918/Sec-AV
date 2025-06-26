import os
import hashlib
import yara
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import magic
import pefile
import ssdeep
import tlsh
from typing import Dict, List, Tuple, Optional, Any
import logging
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from .config import secure_config
from .logger import SecureLogger
from .signatures import AdvancedSignatureManager
from .ml_detector import EnsembleMLDetector
from .database import db_manager

class BehavioralAnalyzer:
    """Behavioral analysis component"""
    
    def __init__(self):
        self.logger = SecureLogger("BehavioralAnalyzer")
        self.patterns = {}
        self.detected_behaviors = []
    
    def load_patterns(self):
        """Load behavioral patterns"""
        # Placeholder implementation
        self.patterns = {
            'file_operations': ['CreateFile', 'WriteFile', 'DeleteFile'],
            'registry_operations': ['RegSetValue', 'RegDeleteKey'],
            'network_operations': ['connect', 'send', 'recv']
        }
    
    def analyze_file(self, file_path: str) -> float:
        """Analyze file for behavioral indicators"""
        # Placeholder implementation
        return 0.0
    
    def get_detected_behaviors(self) -> List[str]:
        """Get list of detected behaviors"""
        return self.detected_behaviors

class HeuristicEngine:
    """Heuristic analysis engine"""
    
    def __init__(self):
        self.logger = SecureLogger("HeuristicEngine")
        self.rules = {}
        self.indicators = []
    
    def load_rules(self):
        """Load heuristic rules"""
        # Placeholder implementation
        self.rules = {
            'entropy_check': {'threshold': 7.0, 'weight': 0.3},
            'suspicious_strings': {'patterns': ['eval', 'exec'], 'weight': 0.4},
            'file_size': {'min_size': 1024, 'weight': 0.2}
        }
    
    def analyze_file(self, file_path: str) -> float:
        """Analyze file using heuristic rules"""
        score = 0.0
        self.indicators = []
        
        try:
            # File size check
            file_size = os.path.getsize(file_path)
            if file_size < self.rules['file_size']['min_size']:
                score += self.rules['file_size']['weight']
                self.indicators.append('Small file size')
            
            # Entropy check
            with open(file_path, 'rb') as f:
                data = f.read(10000)  # First 10KB
            
            entropy = self._calculate_entropy(data)
            if entropy > self.rules['entropy_check']['threshold']:
                score += self.rules['entropy_check']['weight']
                self.indicators.append(f'High entropy: {entropy:.2f}')
            
            # String pattern check
            try:
                content = data.decode('utf-8', errors='ignore')
                for pattern in self.rules['suspicious_strings']['patterns']:
                    if pattern in content.lower():
                        score += self.rules['suspicious_strings']['weight']
                        self.indicators.append(f'Suspicious string: {pattern}')
            except:
                pass
        
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed: {e}")
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
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
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def get_indicators(self) -> List[str]:
        """Get detected indicators"""
        return self.indicators

class AdvancedThreatDetectionEngine:
    """Advanced multi-layered threat detection engine with AI/ML capabilities"""
    
    def __init__(self):
        self.logger = SecureLogger("ThreatEngine")
        self.signature_manager = AdvancedSignatureManager()
        self.ml_detector = EnsembleMLDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.heuristic_engine = HeuristicEngine()
        
        # Detection thresholds
        self.ml_threshold = secure_config.get("detection.ml_threshold", 0.85)
        self.heuristic_threshold = 0.75
        self.behavioral_threshold = 0.80
        
        # Performance optimization
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self.cache = {}
        self.cache_lock = threading.Lock()
        
        # Initialize detection components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all detection components"""
        try:
            self.logger.info("Initializing advanced threat detection engine...")
            
            # Load YARA rules
            self._load_yara_rules()
            
            # Initialize ML models
            self.ml_detector.initialize()
            
            # Initialize behavioral patterns
            self.behavioral_analyzer.load_patterns()
            
            # Load heuristic rules
            self.heuristic_engine.load_rules()
            
            self.logger.info("Threat detection engine initialized successfully")
            
        except Exception as e:
            self.logger.critical(f"Failed to initialize detection engine: {e}")
            raise
    
    def _load_yara_rules(self):
        """Load and compile YARA rules for signature detection"""
        try:
            rules_path = "signatures/yara_rules"
            if os.path.exists(rules_path):
                rule_files = []
                for root, dirs, files in os.walk(rules_path):
                    for file in files:
                        if file.endswith('.yar') or file.endswith('.yara'):
                            rule_files.append(os.path.join(root, file))
                
                if rule_files:
                    # Compile YARA rules
                    rules_dict = {}
                    for i, rule_file in enumerate(rule_files):
                        rules_dict[f'rule_{i}'] = rule_file
                    
                    self.yara_rules = yara.compile(filepaths=rules_dict)
                    self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
                else:
                    self.yara_rules = None
                    self.logger.warning("No YARA rules found")
            else:
                self.yara_rules = None
                self.logger.warning("YARA rules directory not found")
                
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file scanning with multiple detection methods"""
        start_time = time.time()
        
        try:
            # Input validation and security checks
            if not self._validate_file_input(file_path):
                return self._create_scan_result(file_path, "ERROR", "Invalid file input", 0.0)
            
            # Check cache first
            file_hash = self._calculate_file_hash(file_path)
            cached_result = self._get_cached_result(file_hash)
            if cached_result:
                return cached_result
            
            # Initialize scan result
            scan_result = {
                "file_path": file_path,
                "file_hash": file_hash,
                "file_size": os.path.getsize(file_path),
                "scan_time": 0,
                "detections": [],
                "threat_score": 0.0,
                "classification": "CLEAN",
                "metadata": {}
            }
            
            # Use signature manager for comprehensive scanning
            signature_scan_result = self.signature_manager.scan_file(file_path)
            
            # Merge results
            scan_result["detections"] = signature_scan_result.get("threats", [])
            scan_result["threat_score"] = self._calculate_threat_score_from_detections(scan_result["detections"])
            scan_result["classification"] = self._classify_threat(scan_result["threat_score"])
            scan_result["metadata"] = signature_scan_result.get("scan_details", {})
            
            # Record scan time
            scan_result["scan_time"] = time.time() - start_time
            
            # Cache result
            self._cache_result(file_hash, scan_result)
            
            # Store in database via signature manager (already handled)
            
            # Log scan result
            self.logger.info(f"Scan completed: {file_path} - {scan_result['classification']} "
                           f"(Score: {scan_result['threat_score']:.2f})")
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Scan failed for {file_path}: {e}")
            return self._create_scan_result(file_path, "ERROR", str(e), 0.0)
    
    def _validate_file_input(self, file_path: str) -> bool:
        """Validate file input for security"""
        try:
            # Check if file exists and is readable
            if not os.path.isfile(file_path):
                return False
            
            # Check file size limits
            max_size = secure_config.get("security.max_file_size", 100 * 1024 * 1024)
            if os.path.getsize(file_path) > max_size:
                self.logger.warning(f"File too large: {file_path}")
                return False
            
            # Check for path traversal attempts
            normalized_path = os.path.normpath(file_path)
            if ".." in normalized_path or normalized_path.startswith("/"):
                self.logger.warning(f"Suspicious file path: {file_path}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"File validation failed: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate secure hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            return ""
    
    def _calculate_threat_score_from_detections(self, detections: List[Dict[str, Any]]) -> float:
        """Calculate threat score from detections"""
        if not detections:
            return 0.0
        
        # Weighted scoring based on detection method reliability
        weights = {
            'hash_signature': 0.9,
            'pattern_signature': 0.7,
            'yara_match': 0.8,
            'threat_intelligence': 0.85,
            'ml': 0.8,
            'heuristic': 0.6,
            'behavioral': 0.7
        }
        
        severity_multipliers = {
            'low': 0.3,
            'medium': 0.6,
            'high': 1.0,
            'critical': 1.2
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for detection in detections:
            detection_type = detection.get('type', 'unknown')
            severity = detection.get('severity', 'medium')
            
            weight = weights.get(detection_type, 0.5)
            severity_mult = severity_multipliers.get(severity, 0.6)
            
            score = weight * severity_mult
            total_score += score
            total_weight += weight
        
        if total_weight > 0:
            return min(total_score / total_weight, 1.0)
        
        return 0.0
    
    def _classify_threat(self, threat_score: float) -> str:
        """Classify threat based on score"""
        if threat_score >= 0.9:
            return "MALICIOUS"
        elif threat_score >= 0.7:
            return "SUSPICIOUS"
        elif threat_score >= 0.3:
            return "POTENTIALLY_UNWANTED"
        else:
            return "CLEAN"
    
    def _get_cached_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result"""
        with self.cache_lock:
            return self.cache.get(file_hash)
    
    def _cache_result(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Cache scan result"""
        with self.cache_lock:
            # Limit cache size
            if len(self.cache) > 1000:
                # Remove oldest entries
                oldest_keys = list(self.cache.keys())[:100]
                for key in oldest_keys:
                    del self.cache[key]
            
            self.cache[file_hash] = result
    
    def _create_scan_result(self, file_path: str, classification: str, 
                          error: str, score: float) -> Dict[str, Any]:
        """Create standardized scan result"""
        return {
            "file_path": file_path,
            "classification": classification,
            "threat_score": score,
            "error": error,
            "scan_time": 0,
            "detections": []
        }
    
    def update_signatures(self) -> bool:
        """Update threat signatures from cloud intelligence"""
        try:
            return self.signature_manager.update_from_cloud()
        except Exception as e:
            self.logger.error(f"Signature update failed: {e}")
            return False
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get engine status and statistics"""
        return {
            "initialized": True,
            "yara_rules_loaded": self.yara_rules is not None,
            "ml_models_loaded": self.ml_detector.is_initialized(),
            "signature_count": self.signature_manager.get_signature_count(),
            "cache_size": len(self.cache),
            "last_update": self.signature_manager.get_last_update(),
            "database_status": db_manager.health_check()
        }
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics from database"""
        return self.signature_manager.get_threat_statistics()
    
    def cleanup_old_data(self, days_to_keep: int = 30) -> int:
        """Clean up old scan data"""
        return self.signature_manager.cleanup_old_data(days_to_keep)