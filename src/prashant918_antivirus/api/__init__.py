"""
Prashant918 Advanced Antivirus - API Module
Web API for remote management and monitoring
"""

try:
    from .web_api import create_app
    HAS_API = True
except ImportError:
    HAS_API = False
    create_app = None

__all__ = []

if HAS_API:
    __all__.append('create_app')
