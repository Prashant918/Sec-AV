"""
Unified Threat Engine - Core threat detection orchestrator
"""

import os
import sys
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

class UnifiedThreatEngine:
    """
    Unified threat detection engine that orchestrates various detection methods
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = SecureLogger("UnifiedThreatEngine")
        self.config = config or {}
        self.initialized = False
        
        # Detection engines
        self.advanced_engine = None
        self.ml_detector = None
        self.signature_manager = None
        
        self._initialize_engines()
    
    def _initialize_engines(self):
        """Initialize available detection engines"""
        try:
            # Try to load advanced threat detection engine
            try:
                from ..antivirus.engine import AdvancedThreatDetectionEngine
                self.advanced_engine = AdvancedThreatDetectionEngine()
                self.logger.info("Advanced threat detection engine loaded")
            except ImportError as e:
                self.logger.warning(f"Advanced engine not available: {e}")
            
            # Try to load ML detector
            try:
                from ..antivirus.ml_detector import EnsembleMLDetector
                self.ml_detector = EnsembleMLDetector()
                self.logger.info("ML detector loaded")
            except ImportError as e:
                self.logger.warning(f"ML detector not available: {e}")
            
            # Try to load signature manager
            try:
                from ..antivirus.signatures import AdvancedSignatureManager
                self.signature_manager = AdvancedSignatureManager()
                self.logger.info("Signature manager loaded")
            except ImportError as e:
                self.logger.warning(f"Signature manager not available: {e}")
            
            self.initialized = True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize engines: {e}")
            raise AntivirusError(f"Engine initialization failed: {e}")
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file using available detection engines
        """
        if not self.initialized:
            return {
                'status': 'error',
                'message': 'Engine not initialized',
                'file_path': file_path
            }
        
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return {
                    'status': 'error',
                    'message': 'File not found',
                    'file_path': str(file_path)
                }
            
            results = {
                'status': 'clean',
                'file_path': str(file_path),
                'threat_level': 'clean',
                'confidence': 0.0,
                'detection_method': 'none',
                'threat_name': None,
                'scan_time': 0.0,
                'engines_used': []
            }
            
            # Use advanced engine if available
            if self.advanced_engine:
                try:
                    advanced_result = self.advanced_engine.scan_file(str(file_path))
                    if hasattr(advanced_result, 'threat_level'):
                        results.update({
                            'status': 'infected' if advanced_result.threat_level.name != 'CLEAN' else 'clean',
                            'threat_level': advanced_result.threat_level.name.lower(),
                            'confidence': advanced_result.confidence,
                            'detection_method': advanced_result.detection_method,
                            'threat_name': advanced_result.threat_name,
                            'scan_time': advanced_result.scan_time
                        })
                        results['engines_used'].append('advanced_engine')
                except Exception as e:
                    self.logger.warning(f"Advanced engine scan failed: {e}")
            
            # Use ML detector if available and no threat found yet
            if self.ml_detector and results['status'] == 'clean':
                try:
                    features = self.ml_detector.extract_features(str(file_path))
                    ml_result = self.ml_detector.predict(features)
                    
                    if ml_result.get('prediction') == 'malicious':
                        results.update({
                            'status': 'infected',
                            'threat_level': 'suspicious',
                            'confidence': ml_result.get('probability', 0.0),
                            'detection_method': 'machine_learning',
                            'threat_name': 'ML_Detection'
                        })
                        results['engines_used'].append('ml_detector')
                except Exception as e:
                    self.logger.warning(f"ML detector scan failed: {e}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed for {file_path}: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'file_path': str(file_path)
            }
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get status of all detection engines"""
        return {
            'initialized': self.initialized,
            'advanced_engine': self.advanced_engine is not None,
            'ml_detector': self.ml_detector is not None,
            'signature_manager': self.signature_manager is not None
        }