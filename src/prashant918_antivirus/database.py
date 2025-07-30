"""
Prashant918 Advanced Antivirus - Enhanced Database Manager
Cross-platform database management with SQLite and Oracle support
"""
import os
import sys
import sqlite3
import threading
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager

# Core imports with error handling
try:
    from .logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from .config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

try:
    from .exceptions import DatabaseError, ConnectionError
except ImportError:
    class DatabaseError(Exception): pass
    class ConnectionError(DatabaseError): pass

# Optional Oracle support
try:
    import cx_Oracle
    HAS_ORACLE = True
except ImportError:
    HAS_ORACLE = False
    cx_Oracle = None

class DatabaseManager:
    """Enhanced database manager with SQLite and Oracle support"""
    
    def __init__(self, db_type: str = None):
        self.logger = SecureLogger("DatabaseManager")
        
        # Determine database type
        self.db_type = db_type or secure_config.get("database.type", "sqlite")
        
        # Connection management
        self.connection = None
        self.connection_lock = threading.Lock()
        self.connection_pool = []
        self.pool_size = secure_config.get("database.pool_size", 5)
        
        # Database paths and configuration
        self._setup_database_config()
        
        # Schema version tracking
        self.schema_version = 1
        self.schema_lock = threading.Lock()
        
        # Performance tracking
        self.query_stats = {
            'total_queries': 0,
            'failed_queries': 0,
            'avg_query_time': 0.0,
            'last_query_time': None
        }
        
        # Initialize database
        self._initialize_database()
    
    def _setup_database_config(self):
        """Setup database configuration"""
        try:
            if self.db_type.lower() == "sqlite":
                # SQLite configuration
                db_dir = Path.home() / ".prashant918_antivirus" / "data"
                db_dir.mkdir(parents=True, exist_ok=True)
                
                self.db_path = secure_config.get(
                    "database.sqlite_path", 
                    str(db_dir / "antivirus.db")
                )
                
                self.connection_string = self.db_path
                
            elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                # Oracle configuration
                oracle_config = secure_config.get("database.oracle", {})
                
                self.oracle_config = {
                    'host': oracle_config.get('host', 'localhost'),
                    'port': oracle_config.get('port', 1521),
                    'service_name': oracle_config.get('service_name', 'XEPDB1'),
                    'username': oracle_config.get('username', 'antivirus'),
                    'password': oracle_config.get('password', ''),
                    'pool_size': oracle_config.get('pool_size', 5),
                    'max_overflow': oracle_config.get('max_overflow', 10)
                }
                
                self.connection_string = (
                    f"{self.oracle_config['username']}/"
                    f"{self.oracle_config['password']}@"
                    f"{self.oracle_config['host']}:"
                    f"{self.oracle_config['port']}/"
                    f"{self.oracle_config['service_name']}"
                )
                
            else:
                # Fallback to SQLite
                self.logger.warning(f"Unsupported database type '{self.db_type}', falling back to SQLite")
                self.db_type = "sqlite"
                self._setup_database_config()
                
        except Exception as e:
            self.logger.error(f"Database configuration setup failed: {e}")
            raise DatabaseError(f"Configuration setup failed: {e}")
    
    def _initialize_database(self):
        """Initialize database connection and schema"""
        try:
            # Test connection
            if not self._test_connection():
                raise ConnectionError("Failed to establish database connection")
            
            # Initialize schema
            self._initialize_schema()
            
            # Setup connection pool for Oracle
            if self.db_type.lower() == "oracle" and HAS_ORACLE:
                self._setup_connection_pool()
            
            self.logger.info(f"Database initialized successfully ({self.db_type})")
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise DatabaseError(f"Initialization failed: {e}")
    
    def _test_connection(self) -> bool:
        """Test database connection"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if self.db_type.lower() == "sqlite":
                    cursor.execute("SELECT 1")
                elif self.db_type.lower() == "oracle":
                    cursor.execute("SELECT 1 FROM DUAL")
                
                result = cursor.fetchone()
                return result is not None
                
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        connection = None
        try:
            with self.connection_lock:
                if self.db_type.lower() == "sqlite":
                    connection = sqlite3.connect(
                        self.db_path,
                        timeout=30,
                        check_same_thread=False
                    )
                    connection.row_factory = sqlite3.Row
                    
                elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                    if self.connection_pool:
                        connection = self.connection_pool.pop()
                    else:
                        connection = cx_Oracle.connect(self.connection_string)
                
                if connection is None:
                    raise ConnectionError("Failed to create database connection")
            
            yield connection
            
        except Exception as e:
            self.logger.error(f"Database connection error: {e}")
            raise DatabaseError(f"Connection error: {e}")
        finally:
            if connection:
                try:
                    if self.db_type.lower() == "sqlite":
                        connection.close()
                    elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                        with self.connection_lock:
                            if len(self.connection_pool) < self.pool_size:
                                self.connection_pool.append(connection)
                            else:
                                connection.close()
                except Exception as e:
                    self.logger.debug(f"Error closing connection: {e}")
    
    def _setup_connection_pool(self):
        """Setup Oracle connection pool"""
        try:
            if not HAS_ORACLE:
                return
            
            for _ in range(self.pool_size):
                try:
                    conn = cx_Oracle.connect(self.connection_string)
                    self.connection_pool.append(conn)
                except Exception as e:
                    self.logger.warning(f"Failed to create pooled connection: {e}")
                    break
            
            self.logger.info(f"Created {len(self.connection_pool)} pooled connections")
            
        except Exception as e:
            self.logger.error(f"Connection pool setup failed: {e}")
    
    def _initialize_schema(self):
        """Initialize database schema"""
        try:
            with self.schema_lock:
                # Check current schema version
                current_version = self._get_schema_version()
                
                if current_version < self.schema_version:
                    self._create_tables()
                    self._update_schema_version()
                    self.logger.info("Database schema initialized/updated")
                
        except Exception as e:
            self.logger.error(f"Schema initialization failed: {e}")
            raise DatabaseError(f"Schema initialization failed: {e}")
    
    def _get_schema_version(self) -> int:
        """Get current schema version"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if self.db_type.lower() == "sqlite":
                    cursor.execute("""
                        SELECT name FROM sqlite_master 
                        WHERE type='table' AND name='schema_version'
                    """)
                elif self.db_type.lower() == "oracle":
                    cursor.execute("""
                        SELECT table_name FROM user_tables 
                        WHERE table_name = 'SCHEMA_VERSION'
                    """)
                
                if cursor.fetchone():
                    cursor.execute("SELECT version FROM schema_version ORDER BY id DESC LIMIT 1")
                    result = cursor.fetchone()
                    return result[0] if result else 0
                
                return 0
                
        except Exception as e:
            self.logger.debug(f"Error getting schema version: {e}")
            return 0
    
    def _update_schema_version(self):
        """Update schema version"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO schema_version (version, updated_at) 
                    VALUES (?, ?)
                """, (self.schema_version, datetime.now().isoformat()))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating schema version: {e}")
    
    def _create_tables(self):
        """Create database tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Schema version table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS schema_version (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        version INTEGER NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                
                # Scan results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        file_hash TEXT,
                        file_size INTEGER,
                        scan_time TEXT NOT NULL,
                        threat_level TEXT NOT NULL,
                        threat_name TEXT,
                        confidence REAL,
                        detection_method TEXT,
                        scan_duration REAL,
                        metadata TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Threat signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_type TEXT NOT NULL,
                        signature_value TEXT NOT NULL,
                        threat_name TEXT NOT NULL,
                        severity INTEGER DEFAULT 5,
                        description TEXT,
                        source TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(signature_type, signature_value)
                    )
                """)
                
                # Quarantine items table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS quarantine_items (
                        id TEXT PRIMARY KEY,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        threat_name TEXT NOT NULL,
                        detection_method TEXT NOT NULL,
                        quarantine_time TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'quarantined',
                        metadata TEXT DEFAULT '{}',
                        restore_count INTEGER DEFAULT 0,
                        last_accessed TEXT
                    )
                """)
                
                # System events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS system_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        event_data TEXT,
                        severity TEXT NOT NULL DEFAULT 'info',
                        source TEXT,
                        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Configuration table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS configuration (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        data_type TEXT NOT NULL DEFAULT 'string',
                        description TEXT,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for better performance
                indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_scan_results_file_hash ON scan_results(file_hash)",
                    "CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time ON scan_results(scan_time)",
                    "CREATE INDEX IF NOT EXISTS idx_scan_results_threat_level ON scan_results(threat_level)",
                    "CREATE INDEX IF NOT EXISTS idx_threat_signatures_type ON threat_signatures(signature_type)",
                    "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status)",
                    "CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type)",
                    "CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp)"
                ]
                
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                conn.commit()
                self.logger.info("Database tables created successfully")
                
        except Exception as e:
            self.logger.error(f"Table creation failed: {e}")
            raise DatabaseError(f"Table creation failed: {e}")
    
    def execute_query(self, query: str, params: Tuple = None, 
                     fetch_results: bool = False) -> Optional[List[Dict]]:
        """Execute database query with error handling and performance tracking"""
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                results = None
                if fetch_results:
                    if self.db_type.lower() == "sqlite":
                        results = [dict(row) for row in cursor.fetchall()]
                    else:
                        columns = [desc[0] for desc in cursor.description]
                        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                conn.commit()
                
                # Update statistics
                query_time = time.time() - start_time
                self._update_query_stats(query_time, success=True)
                
                return results
                
        except Exception as e:
            query_time = time.time() - start_time
            self._update_query_stats(query_time, success=False)
            
            self.logger.error(f"Query execution failed: {e}")
            self.logger.debug(f"Failed query: {query}")
            raise DatabaseError(f"Query execution failed: {e}")
    
    def _update_query_stats(self, query_time: float, success: bool):
        """Update query performance statistics"""
        try:
            self.query_stats['total_queries'] += 1
            if not success:
                self.query_stats['failed_queries'] += 1
            
            # Update average query time
            total_time = (self.query_stats['avg_query_time'] * 
                         (self.query_stats['total_queries'] - 1) + query_time)
            self.query_stats['avg_query_time'] = total_time / self.query_stats['total_queries']
            self.query_stats['last_query_time'] = time.time()
            
        except Exception as e:
            self.logger.debug(f"Error updating query stats: {e}")
    
    def store_scan_result(self, scan_result: Dict[str, Any]) -> bool:
        """Store scan result in database"""
        try:
            query = """
                INSERT INTO scan_results 
                (file_path, file_hash, file_size, scan_time, threat_level, 
                 threat_name, confidence, detection_method, scan_duration, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            params = (
                scan_result.get('file_path', ''),
                scan_result.get('file_hash', ''),
                scan_result.get('file_size', 0),
                scan_result.get('scan_time', datetime.now().isoformat()),
                scan_result.get('threat_level', 'unknown'),
                scan_result.get('threat_name', ''),
                scan_result.get('confidence', 0.0),
                scan_result.get('detection_method', ''),
                scan_result.get('scan_duration', 0.0),
                json.dumps(scan_result.get('metadata', {}))
            )
            
            self.execute_query(query, params)
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing scan result: {e}")
            return False
    
    def get_scan_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics from database"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Total scans
            total_query = """
                SELECT COUNT(*) as total_scans FROM scan_results 
                WHERE created_at >= ?
            """
            total_result = self.execute_query(total_query, (cutoff_date,), fetch_results=True)
            total_scans = total_result[0]['total_scans'] if total_result else 0
            
            # Threat statistics
            threat_query = """
                SELECT threat_level, COUNT(*) as count 
                FROM scan_results 
                WHERE created_at >= ? 
                GROUP BY threat_level
            """
            threat_results = self.execute_query(threat_query, (cutoff_date,), fetch_results=True)
            
            threat_stats = {}
            for result in threat_results or []:
                threat_stats[result['threat_level']] = result['count']
            
            # Recent threats
            recent_query = """
                SELECT file_path, threat_name, threat_level, scan_time 
                FROM scan_results 
                WHERE threat_level IN ('malware', 'critical') 
                AND created_at >= ? 
                ORDER BY created_at DESC 
                LIMIT 10
            """
            recent_threats = self.execute_query(recent_query, (cutoff_date,), fetch_results=True)
            
            return {
                'total_scans': total_scans,
                'threat_distribution': threat_stats,
                'recent_threats': recent_threats or [],
                'period_days': days,
                'query_stats': self.query_stats.copy()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting scan statistics: {e}")
            return {'error': str(e)}
    
    def add_threat_signature(self, signature_type: str, signature_value: str,
                           threat_name: str, severity: int = 5, 
                           description: str = '', source: str = '') -> bool:
        """Add threat signature to database"""
        try:
            query = """
                INSERT OR REPLACE INTO threat_signatures 
                (signature_type, signature_value, threat_name, severity, description, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            
            params = (
                signature_type, signature_value, threat_name, severity,
                description, source, datetime.now().isoformat()
            )
            
            self.execute_query(query, params)
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding threat signature: {e}")
            return False
    
    def get_threat_signatures(self, signature_type: str = None) -> List[Dict[str, Any]]:
        """Get threat signatures from database"""
        try:
            if signature_type:
                query = "SELECT * FROM threat_signatures WHERE signature_type = ?"
                params = (signature_type,)
            else:
                query = "SELECT * FROM threat_signatures"
                params = None
            
            results = self.execute_query(query, params, fetch_results=True)
            return results or []
            
        except Exception as e:
            self.logger.error(f"Error getting threat signatures: {e}")
            return []
    
    def log_system_event(self, event_type: str, event_data: Dict[str, Any] = None,
                        severity: str = 'info', source: str = '') -> bool:
        """Log system event to database"""
        try:
            query = """
                INSERT INTO system_events (event_type, event_data, severity, source)
                VALUES (?, ?, ?, ?)
            """
            
            params = (
                event_type,
                json.dumps(event_data or {}),
                severity,
                source
            )
            
            self.execute_query(query, params)
            return True
            
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")
            return False
    
    def get_system_events(self, event_type: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Get system events from database"""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            if event_type:
                query = """
                    SELECT * FROM system_events 
                    WHERE event_type = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                """
                params = (event_type, cutoff_time)
            else:
                query = """
                    SELECT * FROM system_events 
                    WHERE timestamp >= ?
                    ORDER BY
                                        ORDER BY timestamp DESC
                """
                params = (cutoff_time,)
            
            results = self.execute_query(query, params, fetch_results=True)
            
            # Parse event_data JSON
            for result in results or []:
                try:
                    result['event_data'] = json.loads(result['event_data'])
                except (json.JSONDecodeError, TypeError):
                    result['event_data'] = {}
            
            return results or []
            
        except Exception as e:
            self.logger.error(f"Error getting system events: {e}")
            return []
    
    def cleanup_old_data(self, days_to_keep: int = 30) -> Dict[str, int]:
        """Clean up old data from database"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            cleanup_stats = {}
            
            # Clean up old scan results
            scan_query = "DELETE FROM scan_results WHERE created_at < ?"
            self.execute_query(scan_query, (cutoff_date,))
            cleanup_stats['scan_results'] = self.get_affected_rows()
            
            # Clean up old system events
            events_query = "DELETE FROM system_events WHERE timestamp < ?"
            self.execute_query(events_query, (cutoff_date,))
            cleanup_stats['system_events'] = self.get_affected_rows()
            
            # Vacuum database (SQLite only)
            if self.db_type.lower() == "sqlite":
                self.execute_query("VACUUM")
            
            self.logger.info(f"Database cleanup completed: {cleanup_stats}")
            return cleanup_stats
            
        except Exception as e:
            self.logger.error(f"Database cleanup failed: {e}")
            return {'error': str(e)}
    
    def get_affected_rows(self) -> int:
        """Get number of affected rows from last operation"""
        try:
            with self.get_connection() as conn:
                if self.db_type.lower() == "sqlite":
                    return conn.total_changes
                else:
                    return conn.rowcount
        except Exception:
            return 0
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            if self.db_type.lower() == "sqlite":
                # SQLite backup
                import shutil
                shutil.copy2(self.db_path, backup_path)
                
            elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                # Oracle backup (simplified - would need proper Oracle backup tools)
                self.logger.warning("Oracle backup not implemented - use Oracle backup tools")
                return False
            
            self.logger.info(f"Database backup created: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Database backup failed: {e}")
            return False
    
    def restore_database(self, backup_path: str) -> bool:
        """Restore database from backup"""
        try:
            if self.db_type.lower() == "sqlite":
                # SQLite restore
                import shutil
                
                # Close current connections
                self.close_all_connections()
                
                # Restore backup
                shutil.copy2(backup_path, self.db_path)
                
                # Reinitialize
                self._initialize_database()
                
            elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                # Oracle restore (simplified)
                self.logger.warning("Oracle restore not implemented - use Oracle restore tools")
                return False
            
            self.logger.info(f"Database restored from: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Database restore failed: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        try:
            health_status = {
                'database_type': self.db_type,
                'connection_status': 'unknown',
                'schema_version': 0,
                'total_records': {},
                'query_performance': self.query_stats.copy(),
                'disk_usage': {},
                'last_check': datetime.now().isoformat()
            }
            
            # Test connection
            if self._test_connection():
                health_status['connection_status'] = 'healthy'
            else:
                health_status['connection_status'] = 'failed'
                return health_status
            
            # Get schema version
            health_status['schema_version'] = self._get_schema_version()
            
            # Get record counts
            tables = ['scan_results', 'threat_signatures', 'quarantine_items', 'system_events']
            for table in tables:
                try:
                    count_query = f"SELECT COUNT(*) as count FROM {table}"
                    result = self.execute_query(count_query, fetch_results=True)
                    health_status['total_records'][table] = result[0]['count'] if result else 0
                except Exception as e:
                    health_status['total_records'][table] = f"Error: {e}"
            
            # Get disk usage (SQLite only)
            if self.db_type.lower() == "sqlite":
                try:
                    db_path = Path(self.db_path)
                    if db_path.exists():
                        size_bytes = db_path.stat().st_size
                        health_status['disk_usage'] = {
                            'size_bytes': size_bytes,
                            'size_mb': round(size_bytes / (1024 * 1024), 2)
                        }
                except Exception as e:
                    health_status['disk_usage'] = {'error': str(e)}
            
            return health_status
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                'connection_status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    def optimize_database(self) -> Dict[str, Any]:
        """Optimize database performance"""
        try:
            optimization_results = {}
            
            if self.db_type.lower() == "sqlite":
                # SQLite optimization
                optimizations = [
                    ("ANALYZE", "Update table statistics"),
                    ("VACUUM", "Reclaim unused space"),
                    ("PRAGMA optimize", "Optimize query planner")
                ]
                
                for command, description in optimizations:
                    try:
                        start_time = time.time()
                        self.execute_query(command)
                        duration = time.time() - start_time
                        
                        optimization_results[command] = {
                            'status': 'completed',
                            'duration': round(duration, 2),
                            'description': description
                        }
                    except Exception as e:
                        optimization_results[command] = {
                            'status': 'failed',
                            'error': str(e),
                            'description': description
                        }
            
            elif self.db_type.lower() == "oracle" and HAS_ORACLE:
                # Oracle optimization (basic)
                try:
                    self.execute_query("BEGIN DBMS_STATS.GATHER_SCHEMA_STATS(USER); END;")
                    optimization_results['gather_stats'] = {
                        'status': 'completed',
                        'description': 'Updated table statistics'
                    }
                except Exception as e:
                    optimization_results['gather_stats'] = {
                        'status': 'failed',
                        'error': str(e)
                    }
            
            self.logger.info(f"Database optimization completed: {optimization_results}")
            return optimization_results
            
        except Exception as e:
            self.logger.error(f"Database optimization failed: {e}")
            return {'error': str(e)}
    
    def get_configuration(self, key: str = None) -> Union[Dict[str, Any], Any]:
        """Get configuration from database"""
        try:
            if key:
                query = "SELECT value, data_type FROM configuration WHERE key = ?"
                params = (key,)
                results = self.execute_query(query, params, fetch_results=True)
                
                if results:
                    value = results[0]['value']
                    data_type = results[0]['data_type']
                    
                    # Convert value based on data type
                    if data_type == 'json':
                        return json.loads(value)
                    elif data_type == 'int':
                        return int(value)
                    elif data_type == 'float':
                        return float(value)
                    elif data_type == 'bool':
                        return value.lower() in ('true', '1', 'yes')
                    else:
                        return value
                
                return None
            else:
                query = "SELECT key, value, data_type FROM configuration"
                results = self.execute_query(query, fetch_results=True)
                
                config = {}
                for result in results or []:
                    key = result['key']
                    value = result['value']
                    data_type = result['data_type']
                    
                    # Convert value based on data type
                    if data_type == 'json':
                        config[key] = json.loads(value)
                    elif data_type == 'int':
                        config[key] = int(value)
                    elif data_type == 'float':
                        config[key] = float(value)
                    elif data_type == 'bool':
                        config[key] = value.lower() in ('true', '1', 'yes')
                    else:
                        config[key] = value
                
                return config
                
        except Exception as e:
            self.logger.error(f"Error getting configuration: {e}")
            return None if key else {}
    
    def set_configuration(self, key: str, value: Any, description: str = '') -> bool:
        """Set configuration in database"""
        try:
            # Determine data type
            if isinstance(value, bool):
                data_type = 'bool'
                value_str = str(value).lower()
            elif isinstance(value, int):
                data_type = 'int'
                value_str = str(value)
            elif isinstance(value, float):
                data_type = 'float'
                value_str = str(value)
            elif isinstance(value, (dict, list)):
                data_type = 'json'
                value_str = json.dumps(value)
            else:
                data_type = 'string'
                value_str = str(value)
            
            query = """
                INSERT OR REPLACE INTO configuration 
                (key, value, data_type, description, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """
            
            params = (key, value_str, data_type, description, datetime.now().isoformat())
            self.execute_query(query, params)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting configuration: {e}")
            return False
    
    def close_all_connections(self):
        """Close all database connections"""
        try:
            with self.connection_lock:
                # Close pooled connections
                for conn in self.connection_pool:
                    try:
                        conn.close()
                    except Exception as e:
                        self.logger.debug(f"Error closing pooled connection: {e}")
                
                self.connection_pool.clear()
                
                # Close main connection if exists
                if self.connection:
                    try:
                        self.connection.close()
                        self.connection = None
                    except Exception as e:
                        self.logger.debug(f"Error closing main connection: {e}")
            
            self.logger.info("All database connections closed")
            
        except Exception as e:
            self.logger.error(f"Error closing connections: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close_all_connections()
    
    def __del__(self):
        """Destructor"""
        try:
            self.close_all_connections()
        except Exception:
            pass

# Global database manager instance
db_manager = None

def get_database_manager() -> DatabaseManager:
    """Get global database manager instance"""
    global db_manager
    
    if db_manager is None:
        db_manager = DatabaseManager()
    
    return db_manager

def initialize_database(db_type: str = None) -> bool:
    """Initialize global database manager"""
    global db_manager
    
    try:
        db_manager = DatabaseManager(db_type)
        return True
    except Exception as e:
        logger = SecureLogger("DatabaseInit")
        logger.error(f"Database initialization failed: {e}")
        return False

# Export main components
__all__ = [
    'DatabaseManager',
    'DatabaseError',
    'ConnectionError',
    'get_database_manager',
    'initialize_database'
]

