"""
Prashant918 Advanced Antivirus
Enterprise-grade AI-powered cybersecurity solution
"""

__version__ = "1.0.2"
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
    
    # Core components
    from .core.engine import UnifiedThreatEngine
    from .core.scanner import FileScanner
    from .core.quarantine import QuarantineManager
    from .database.manager import db_manager
    
    # Optional components
    try:
        from .gui.main_window import AntivirusGUI
        HAS_GUI = True
    except ImportError:
        HAS_GUI = False
        logger.warning("GUI components not available")
    
    try:
        from .api.web_api import create_app
        HAS_API = True
    except ImportError:
        HAS_API = False
        logger.warning("API components not available")
    
    try:
        from .service.service_manager import ServiceManager
        HAS_SERVICE = True
    except ImportError:
        HAS_SERVICE = False
        logger.warning("Service management not available")
    
    # Component availability
    COMPONENTS = {
        'engine': True,
        'scanner': True,
        'quarantine': True,
        'database': True,
        'gui': HAS_GUI,
        'api': HAS_API,
        'service': HAS_SERVICE
    }
    
    logger.info("Prashant918 Advanced Antivirus initialized successfully")
    
except ImportError as e:
    print(f"Warning: Failed to import core components: {e}")
    COMPONENTS = {}

# Export main components
__all__ = [
    '__version__',
    '__author__',
    '__email__',
    '__description__',
    'UnifiedThreatEngine',
    'FileScanner',
    'QuarantineManager',
    'db_manager',
    'COMPONENTS'
]

# Add GUI and API if available
if 'HAS_GUI' in locals() and HAS_GUI:
    __all__.append('AntivirusGUI')
    
if 'HAS_API' in locals() and HAS_API:
    __all__.append('create_app')
    
if 'HAS_SERVICE' in locals() and HAS_SERVICE:
    __all__.append('ServiceManager')