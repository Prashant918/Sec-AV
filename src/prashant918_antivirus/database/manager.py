"""
Database Manager - Unified database operations for SQLite and Oracle
"""

import sqlite3
import threading
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from contextlib import contextmanager

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
    from ..exceptions import DatabaseError, ConnectionError, QueryError
except ImportError:
    class DatabaseError(Exception):
        pass
    class ConnectionError(DatabaseError):
        pass
    class QueryError(DatabaseError):
        pass

# Optional Oracle support
try:
    import cx_Oracle
    HAS_ORACLE = True
except ImportError:
    HAS_ORACLE = False
    cx_Oracle = None


class DatabaseManager:
    """
    Unified database manager supporting SQLite and Oracle
    """
    
    def __init__(self):
        self.logger = SecureLogger("DatabaseManager")
        self.db_type = secure_config.get('database.type', 'sqlite')
        self.connection_pool = {}
        self.lock = threading.Lock()
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database connection and tables"""
        try:
            if self.db_type == 'sqlite':
                self._initialize_sqlite()
            elif self.db_type == 'oracle' and HAS_ORACLE:
                self._initialize_oracle()
            else:
                self.logger.warning(f"Unsupported database type: {self.db_type}, falling back to SQLite")
                self.db_type = 'sqlite'
                self._initialize_sqlite()
            
            # Create tables
            self._create_tables()
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise DatabaseError(f"Failed to initialize database: {e}")
    
    def _initialize_sqlite(self):
        """Initialize SQLite database"""
        db_path = secure_config.get('database.sqlite_path', 
                                   str(Path.home() / ".prashant918_antivirus" / "antivirus.db"))
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.connection_string = db_path
        self.logger.info(f"Using SQLite database: {db_path}")
    
    def _initialize_oracle(self):
        """Initialize Oracle database connection"""
        if not HAS_ORACLE:
            raise DatabaseError("Oracle support not available - cx_Oracle not installed")
        
        oracle_config = {
            'host': secure_config.get('database.oracle.host', 'localhost'),
            'port': secure_config.get('database.oracle.port', 1521),
            'service_name': secure_config.get('database.oracle.service_name', 'XE'),
            'username': secure_config.get('database.oracle.username', 'antivirus'),
            'password': secure_config.get('database.oracle.password', 'password')
        }
        
        dsn = cx_Oracle.makedsn(
            oracle_config['host'],
            oracle_config['port'],
            service_name=oracle_config['service_name']
        )
        
        self.connection_string = f"{oracle_config['username']}/{oracle_config['password']}@{dsn}"
        self.logger.info(f"Using Oracle database: {oracle_config['host']}:{oracle_config['port']}")
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        connection = None
        try:
            if self.db_type == 'sqlite':
                connection = sqlite3.connect(self.connection_string)
                connection.row_factory = sqlite3.Row
            elif self.db_type == 'oracle':
                connection = cx_Oracle.connect(self.connection_string)
            
            yield connection
            
        except Exception as e:
            if connection:
                connection.rollback()
            self.logger.error(f"Database connection error: {e}")
            raise ConnectionError(f"Database connection failed: {e}")
        finally:
            if connection:
                connection.close()
    
    def _create_tables(self):
        """Create necessary database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_type TEXT NOT NULL,
                signature_data BLOB NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS hash_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                hash_type TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(file_hash, hash_type)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                scan_time REAL,
                threat_score REAL,
                threat_level TEXT,
                detection_method TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_details TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS quarantine_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_id TEXT UNIQUE NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                threat_name TEXT,
                detection_method TEXT,
                quarantine_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'QUARANTINED',
                metadata TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_level TEXT NOT NULL,
                component TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                threat_name TEXT,
                threat_family TEXT,
                confidence REAL,
                source TEXT,
                last_seen TIMESTAMP,
                detection_count INTEGER DEFAULT 1,
                total_scans INTEGER DEFAULT 1,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(file_hash, source)
            )
            """
        ]
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_hash_signatures_hash ON hash_signatures(file_hash)",
            "CREATE INDEX IF NOT EXISTS idx_scan_results_date ON scan_results(scan_date)",
            "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status)",
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_hash ON threat_intelligence(file_hash)",
            "CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp)"
        ]
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create tables
                for table_sql in tables:
                    cursor.execute(table_sql)
                
                # Create indexes
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                conn.commit()
                self.logger.info("Database tables created successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to create tables: {e}")
            raise DatabaseError(f"Table creation failed: {e}")
    
    def execute_query(self, query: str, params: Optional[Union[Tuple, Dict]] = None) -> List[Dict]:
        """Execute SELECT query and return results"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if self.db_type == 'sqlite':
                    columns = [description[0] for description in cursor.description]
                    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
                else:  # Oracle
                    columns = [col[0] for col in cursor.description]
                    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                return results
                
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise QueryError(f"Query failed: {e}", query=query)
    
    def execute_command(self, command: str, params: Optional[Union[Tuple, Dict]] = None) -> int:
        """Execute INSERT/UPDATE/DELETE command and return affected rows"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(command, params)
                else:
                    cursor.execute(command)
                
                conn.commit()
                return cursor.rowcount
                
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise QueryError(f"Command failed: {e}", query=command)
    
    def insert_signature(self, signature_type: str, signature_data: bytes, 
                        threat_name: str, severity: str, description: str = None) -> int:
        """Insert new signature into database"""
        query = """
            INSERT INTO signatures (signature_type, signature_data, threat_name, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """
        params = (signature_type, signature_data, threat_name, severity, description)
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Failed to insert signature: {e}")
            raise DatabaseError(f"Signature insertion failed: {e}")
    
    def insert_hash_signature(self, file_hash: str, hash_type: str, 
                             threat_name: str, severity: str, source: str = None) -> bool:
        """Insert hash signature with conflict handling"""
        query = """
            INSERT OR REPLACE INTO hash_signatures 
            (file_hash, hash_type, threat_name, severity, source)
            VALUES (?, ?, ?, ?, ?)
        """
        params = (file_hash, hash_type, threat_name, severity, source)
        
        try:
            self.execute_command(query, params)
            return True
        except Exception as e:
            self.logger.error(f"Failed to insert hash signature: {e}")
            return False
    
    def get_hash_signature(self, file_hash: str, hash_type: str = None) -> Optional[Dict]:
        """Get hash signature by hash value"""
        if hash_type:
            query = "SELECT * FROM hash_signatures WHERE file_hash = ? AND hash_type = ?"
            params = (file_hash, hash_type)
        else:
            query = "SELECT * FROM hash_signatures WHERE file_hash = ?"
            params = (file_hash,)
        
        results = self.execute_query(query, params)
        return results[0] if results else None
    
    def insert_scan_result(self, file_path: str, file_hash: str, file_size: int,
                          scan_time: float, threat_score: float, threat_level: str,
                          detection_method: str, scan_details: Dict = None) -> int:
        """Insert scan result into database"""
        query = """
            INSERT INTO scan_results 
            (file_path, file_hash, file_size, scan_time, threat_score, 
             threat_level, detection_method, scan_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        details_json = json.dumps(scan_details) if scan_details else None
        params = (file_path, file_hash, file_size, scan_time, threat_score,
                 threat_level, detection_method, details_json)
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Failed to insert scan result: {e}")
            raise DatabaseError(f"Scan result insertion failed: {e}")
    
    def get_scan_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics for the specified number of days"""
        query = """
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN threat_level != 'clean' THEN 1 END) as threats_found,
                AVG(scan_time) as avg_scan_time,
                MAX(scan_date) as last_scan
            FROM scan_results 
            WHERE scan_date >= datetime('now', '-{} days')
        """.format(days)
        
        results = self.execute_query(query)
        return results[0] if results else {}
    
    def cleanup_old_records(self, table: str, date_column: str, retention_days: int) -> int:
        """Clean up old records from specified table"""
        query = f"""
            DELETE FROM {table} 
            WHERE {date_column} < datetime('now', '-{retention_days} days')
        """
        
        try:
            return self.execute_command(query)
        except Exception as e:
            self.logger.error(f"Failed to cleanup old records from {table}: {e}")
            return 0
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics"""
        info = {
            'database_type': self.db_type,
            'connection_string': self.connection_string if self.db_type == 'sqlite' else '[REDACTED]',
            'tables': {}
        }
        
        # Get table statistics
        tables = ['signatures', 'hash_signatures', 'scan_results', 'quarantine_items', 
                 'system_logs', 'threat_intelligence']
        
        for table in tables:
            try:
                count_query = f"SELECT COUNT(*) as count FROM {table}"
                result = self.execute_query(count_query)
                info['tables'][table] = result[0]['count'] if result else 0
            except Exception as e:
                self.logger.debug(f"Could not get count for table {table}: {e}")
                info['tables'][table] = 'unknown'
        
        return info
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            if self.db_type == 'sqlite':
                import shutil
                shutil.copy2(self.connection_string, backup_path)
                self.logger.info(f"Database backed up to: {backup_path}")
                return True
            else:
                self.logger.warning("Database backup not implemented for Oracle")
                return False
        except Exception as e:
            self.logger.error(f"Database backup failed: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Optimize database (SQLite only)"""
        try:
            if self.db_type == 'sqlite':
                with self.get_connection() as conn:
                    conn.execute("VACUUM")
                    conn.commit()
                self.logger.info("Database vacuumed successfully")
                return True
            else:
                self.logger.info("Database vacuum not applicable for Oracle")
                return True
        except Exception as e:
            self.logger.error(f"Database vacuum failed: {e}")
            return False

# Global database manager instance
db_manager = DatabaseManager()