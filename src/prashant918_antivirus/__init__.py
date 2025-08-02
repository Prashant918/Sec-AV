"""
Prashant918 Advanced Antivirus
Enterprise-grade AI-powered cybersecurity solution
"""

__version__ = "1.0.3"
__author__ = "Prashant918"
__email__ = "prashant918@example.com"
__description__ = "Advanced AI-powered antivirus system with behavioral analysis and cloud intelligence"

import sys
import os
from pathlib import Path

# Minimum Python version check
if sys.version_info < (3, 8):
    raise RuntimeError("Python 3.8 or higher is required")

# Add src directory to path for development
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Core imports with graceful degradation
try:
    from .logger import SecureLogger
    from .config import secure_config
    from .exceptions import AntivirusError
    
    # Initialize logging
    logger = SecureLogger("Prashant918AV")
    logger.info(f"Prashant918 Advanced Antivirus v{__version__} initializing...")
    
    # Core components - import with error handling
    try:
        from .core.engine import UnifiedThreatEngine
        HAS_ENGINE = True
    except ImportError as e:
        logger.warning(f"Unified threat engine not available: {e}")
        HAS_ENGINE = False
        UnifiedThreatEngine = None
    
    try:
        from .core.scanner import FileScanner
        HAS_SCANNER = True
    except ImportError as e:
        logger.warning(f"File scanner not available: {e}")
        HAS_SCANNER = False
        FileScanner = None
    
    try:
        from .core.quarantine import QuarantineManager
        HAS_QUARANTINE = True
    except ImportError as e:
        logger.warning(f"Quarantine manager not available: {e}")
        HAS_QUARANTINE = False
        QuarantineManager = None
    
    try:
        from .database.manager import db_manager
        HAS_DATABASE = True
    except ImportError as e:
        logger.warning(f"Database manager not available: {e}")
        HAS_DATABASE = False
        db_manager = None
    
    # Optional components
    try:
        from .gui.main_window import AntivirusGUI
        HAS_GUI = True
    except ImportError as e:
        HAS_GUI = False
        AntivirusGUI = None
        logger.warning("GUI components not available")
    
    try:
        from .api.web_api import create_app
        HAS_API = True
    except ImportError as e:
        HAS_API = False
        create_app = None
        logger.warning("API components not available")
    
    try:
        from .service.service_manager import ServiceManager
        HAS_SERVICE = True
    except ImportError as e:
        HAS_SERVICE = False
        ServiceManager = None
        logger.warning("Service management not available")
    
    # Component availability
    COMPONENTS = {
        'engine': HAS_ENGINE,
        'scanner': HAS_SCANNER,
        'quarantine': HAS_QUARANTINE,
        'database': HAS_DATABASE,
        'gui': HAS_GUI,
        'api': HAS_API,
        'service': HAS_SERVICE
    }
    
    logger.info("Prashant918 Advanced Antivirus initialized successfully")
    
except ImportError as e:
    print(f"Warning: Failed to import core components: {e}")
    COMPONENTS = {}
    HAS_ENGINE = HAS_SCANNER = HAS_QUARANTINE = HAS_DATABASE = False
    HAS_GUI = HAS_API = HAS_SERVICE = False
    UnifiedThreatEngine = FileScanner = QuarantineManager = db_manager = None
    AntivirusGUI = create_app = ServiceManager = None

# Export main components
__all__ = [
    '__version__',
    '__author__',
    '__email__',
    '__description__',
    'COMPONENTS',
]

# Add available components to exports
if HAS_ENGINE and UnifiedThreatEngine:
    __all__.append('UnifiedThreatEngine')
if HAS_SCANNER and FileScanner:
    __all__.append('FileScanner')
if HAS_QUARANTINE and QuarantineManager:
    __all__.append('QuarantineManager')
if HAS_DATABASE and db_manager:
    __all__.append('db_manager')
if HAS_GUI and AntivirusGUI:
    __all__.append('AntivirusGUI')
if HAS_API and create_app:
    __all__.append('create_app')
if HAS_SERVICE and ServiceManager:
    __all__.append('ServiceManager')