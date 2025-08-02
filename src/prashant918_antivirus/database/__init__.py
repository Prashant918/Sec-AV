"""
Database Management Components
"""

try:
    from .manager import DatabaseManager, db_manager
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False
    DatabaseManager = None
    db_manager = None

__all__ = []

if HAS_DATABASE:
    __all__.extend(['DatabaseManager', 'db_manager'])
