"""
Prashant918 Advanced Antivirus - Unified Database Manager
Consolidated database management for Oracle and SQLite
"""

import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
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

# Optional Oracle support
try:
    import cx_Oracle
    HAS_ORACLE = True
except ImportError:
    HAS_ORACLE = False
    cx_Oracle = None


class DatabaseManager:
    """
    Unified database manager supporting both SQLite and Oracle
    """
    
    def __init__(self):
        self.logger = SecureLogger("DatabaseManager")
        self.db_type = secure_config.get("database.type", "sqlite")
        self.connection = None
        self.connection_lock = threading.Lock()
        
        # Database paths and configuration
        self.sqlite_path = secure_config.get(
            "database.sqlite_path", 
            str(Path.home() / ".prashant918_antivirus" / "data" / "antivirus.db")
        )
        
        self.oracle_config = secure_config.get("database.oracle", {
            "host": "localhost",
            "port": 1521,
            "service_name": "XEPDB1",
            "username": "antivirus",
            "password": "",
            "pool_size": 5,
            "max_overflow": 10
        })
        
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize database connection and create tables"""
        try:
            if self.db_type.lower() == "oracle" and HAS_ORACLE:
                self._initialize_oracle()
            else:
                self._initialize_sqlite()
                
            self._create_tables()
            self.logger.info(f"Database initialized successfully ({self.db_type})")
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            # Fallback to SQLite
            if self.db_type.lower() != "sqlite":
                self.logger.info("Falling back to SQLite database")
                self.db_type = "sqlite"
                self._initialize_sqlite()
                self._create_tables()
                
    def _initialize_sqlite(self):
        """Initialize SQLite database"""
        try:
            # Ensure directory exists
            db_path = Path(self.sqlite_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.connection = sqlite3.connect(
                self.sqlite_path,
                check_same_thread=False,
                timeout=30.0
            )
            
            # Enable foreign keys and WAL mode
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.execute("PRAGMA synchronous = NORMAL")
            self.connection.commit()
            
        except Exception as e:
            raise Exception(f"SQLite initialization failed: {e}")
            
    def _initialize_oracle(self):
        """Initialize Oracle database connection"""
        if not HAS_ORACLE:
            raise Exception("Oracle client not available")
            
        try:
            dsn = cx_Oracle.makedsn(
                self.oracle_config["host"],
                self.oracle_config["port"],
                service_name=self.oracle_config["service_name"]
            )
            
            self.connection = cx_Oracle.connect(
                user=self.oracle_config["username"],
                password=self.oracle_config["password"],
                dsn=dsn
            )
            
        except Exception as e:
            raise Exception(f"Oracle initialization failed: {e}")
            
    def _create_tables(self):
        """Create database tables"""
        if self.db_type.lower() == "oracle":
            self._create_oracle_tables()
        else:
            self._create_sqlite_tables()
            
    def _create_sqlite_tables(self):
        """Create SQLite tables"""
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
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                extra_data TEXT
            )
            """
        ]
        
        cursor = self.connection.cursor()
        for table_sql in tables:
            cursor.execute(table_sql)
        self.connection.commit()
        
    def _create_oracle_tables(self):
        """Create Oracle tables"""
        tables = [
            """
            CREATE TABLE signatures (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                signature_type VARCHAR2(50) NOT NULL,
                signature_data BLOB NOT NULL,
                threat_name VARCHAR2(255) NOT NULL,
                severity VARCHAR2(20) NOT NULL,
                description CLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE hash_signatures (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                file_hash VARCHAR2(128) NOT NULL,
                hash_type VARCHAR2(10) NOT NULL,
                threat_name VARCHAR2(255) NOT NULL,
                severity VARCHAR2(20) NOT NULL,
                source VARCHAR2(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uk_hash_signatures UNIQUE (file_hash, hash_type)
            )
            """,
            """
            CREATE TABLE scan_results (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                file_path VARCHAR2(4000) NOT NULL,
                file_hash VARCHAR2(128),
                file_size NUMBER,
                scan_time NUMBER,
                threat_score NUMBER(3,2),
                threat_level VARCHAR2(20),
                detection_method VARCHAR2(50),
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_details CLOB
            )
            """,
            """
            CREATE TABLE quarantine_items (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                quarantine_id VARCHAR2(32) UNIQUE NOT NULL,
                original_path VARCHAR2(4000) NOT NULL,
                quarantine_path VARCHAR2(4000) NOT NULL,
                file_hash VARCHAR2(128),
                file_size NUMBER,
                threat_name VARCHAR2(255),
                detection_method VARCHAR2(50),
                quarantine_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR2(20) DEFAULT 'QUARANTINED',
                metadata CLOB
            )
            """,
            """
            CREATE TABLE system_logs (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                log_level VARCHAR2(10) NOT NULL,
                component VARCHAR2(50) NOT NULL,
                message CLOB NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                extra_data CLOB
            )
            """
        ]
        
        cursor = self.connection.cursor()
        for table_sql in tables:
            try:
                cursor.execute(table_sql)
            except Exception as e:
                if "already exists" not in str(e).lower():
                    raise
        self.connection.commit()
        
    @contextmanager
    def get_cursor(self):
        """Get database cursor with automatic cleanup"""
        with self.connection_lock:
            cursor = self.connection.cursor()
            try:
                yield cursor
            finally:
                cursor.close()
                
    def execute_query(self, query: str, params: Optional[Union[tuple, dict]] = None) -> List[Dict]:
        """Execute SELECT query and return results"""
        try:
            with self.get_cursor() as cursor:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                    
                columns = [desc[0] for desc in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                    
                return results
                
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            return []
            
    def execute_command(self, command: str, params: Optional[Union[tuple, dict]] = None) -> bool:
        """Execute INSERT/UPDATE/DELETE command"""
        try:
            with self.get_cursor() as cursor:
                if params:
                    cursor.execute(command, params)
                else:
                    cursor.execute(command)
                    
                self.connection.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            self.connection.rollback()
            return False
            
    def store_scan_result(self, result_data: Dict) -> bool:
        """Store scan result in database"""
        query = """
        INSERT INTO scan_results 
        (file_path, file_hash, file_size, scan_time, threat_score, 
         threat_level, detection_method, scan_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            result_data.get('file_path'),
            result_data.get('file_hash'),
            result_data.get('file_size'),
            result_data.get('scan_time'),
            result_data.get('threat_score'),
            result_data.get('threat_level'),
            result_data.get('detection_method'),
            str(result_data.get('metadata', {}))
        )
        
        return self.execute_command(query, params)
        
    def store_quarantine_item(self, quarantine_data: Dict) -> bool:
        """Store quarantine item in database"""
        query = """
        INSERT INTO quarantine_items 
        (quarantine_id, original_path, quarantine_path, file_hash, 
         file_size, threat_name, detection_method, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            quarantine_data.get('quarantine_id'),
            quarantine_data.get('original_path'),
            quarantine_data.get('quarantine_path'),
            quarantine_data.get('file_hash'),
            quarantine_data.get('file_size'),
            quarantine_data.get('threat_name'),
            quarantine_data.get('detection_method'),
            str(quarantine_data.get('metadata', {}))
        )
        
        return self.execute_command(query, params)
        
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics from database"""
        queries = {
            'total_scans': "SELECT COUNT(*) as count FROM scan_results",
            'threats_detected': "SELECT COUNT(*) as count FROM scan_results WHERE threat_level != 'clean'",
            'quarantined_files': "SELECT COUNT(*) as count FROM quarantine_items WHERE status = 'QUARANTINED'",
            'recent_scans': """
                SELECT COUNT(*) as count FROM scan_results 
                WHERE scan_date > datetime('now', '-24 hours')
            """ if self.db_type == 'sqlite' else """
                SELECT COUNT(*) as count FROM scan_results 
                WHERE scan_date > SYSDATE - 1
            """
        }
        
        stats = {}
        for key, query in queries.items():
            try:
                result = self.execute_query(query)
                stats[key] = result[0]['count'] if result else 0
            except Exception as e:
                self.logger.error(f"Failed to get {key}: {e}")
                stats[key] = 0
                
        return stats
        
    def cleanup_old_records(self, days: int = 30) -> bool:
        """Clean up old database records"""
        try:
            if self.db_type == 'sqlite':
                queries = [
                    f"DELETE FROM scan_results WHERE scan_date < datetime('now', '-{days} days')",
                    f"DELETE FROM system_logs WHERE timestamp < datetime('now', '-{days} days')"
                ]
            else:
                queries = [
                    f"DELETE FROM scan_results WHERE scan_date < SYSDATE - {days}",
                    f"DELETE FROM system_logs WHERE timestamp < SYSDATE - {days}"
                ]
                
            for query in queries:
                self.execute_command(query)
                
            self.logger.info(f"Cleaned up records older than {days} days")
            return True
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
            return False
            
    def close(self):
        """Close database connection"""
        try:
            if self.connection:
                self.connection.close()
                self.logger.info("Database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing database: {e}")


# Global database manager instance
db_manager = DatabaseManager()
