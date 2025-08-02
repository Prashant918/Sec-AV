"""
Antivirus Detection Components
"""

# Import detection components with error handling
try:
    from .engine import AdvancedThreatDetectionEngine
    HAS_ENGINE = True
except ImportError:
    HAS_ENGINE = False
    AdvancedThreatDetectionEngine = None

try:
    from .ml_detector import EnsembleMLDetector
    HAS_ML_DETECTOR = True
except ImportError:
    HAS_ML_DETECTOR = False
    EnsembleMLDetector = None

try:
    from .signatures import AdvancedSignatureManager
    HAS_SIGNATURES = True
except ImportError:
    HAS_SIGNATURES = False
    AdvancedSignatureManager = None

__all__ = []

if HAS_ENGINE:
    __all__.append('AdvancedThreatDetectionEngine')

if HAS_ML_DETECTOR:
    __all__.append('EnsembleMLDetector')

if HAS_SIGNATURES:
    __all__.append('AdvancedSignatureManager')
