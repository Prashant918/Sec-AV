"""
Prashant918 Advanced Antivirus - Database Manager

Advanced database management with Oracle support and SQLite fallback.
"""

import os
import json
import sqlite3
import threading
import time
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

# Try to import Oracle dependencies
try:
    import cx_Oracle
    import oracledb
    from sqlalchemy import create_engine, text, MetaData
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import QueuePool

    ORACLE_AVAILABLE = True
except ImportError:
    ORACLE_AVAILABLE = False
    print("Warning: Oracle dependencies not available, using SQLite fallback")

from .config import secure_config
from .logger import SecureLogger


class DatabaseManager:
    """Database manager with Oracle and SQLite support"""

    def __init__(self):
        self.logger = SecureLogger("DatabaseManager")
        self.connection = None
        self.engine = None
        self.Session = None
        self._lock = threading.Lock()

        # Determine database type
        self.use_oracle = ORACLE_AVAILABLE and secure_config.get(
            "database.use_oracle", False
        )

        if self.use_oracle:
            self.db_config = self._load_oracle_config()
            self._initialize_oracle()
        else:
            self.db_file = "data/antivirus.db"
            self._initialize_sqlite()

        self._create_tables()

    def _load_oracle_config(self) -> Dict[str, Any]:
        """Load Oracle database configuration"""
        return {
            "host": secure_config.get("database.host", "localhost"),
            "port": secure_config.get("database.port", 1521),
            "service_name": secure_config.get("database.service_name", "XEPDB1"),
            "username": secure_config.get("database.username", "antivirus_user"),
            "password": secure_config.get("database.password", "SecurePassword123!"),
            "pool_size": secure_config.get("database.pool_size", 10),
            "max_overflow": secure_config.get("database.max_overflow", 20),
        }

    def _initialize_oracle(self):
        """Initialize Oracle database connection"""
        try:
            connection_string = (
                f"oracle+cx_oracle://{self.db_config['username']}:"
                f"{self.db_config['password']}@"
                f"{self.db_config['host']}:{self.db_config['port']}/"
                f"{self.db_config['service_name']}"
            )

            self.engine = create_engine(
                connection_string,
                poolclass=QueuePool,
                pool_size=self.db_config["pool_size"],
                max_overflow=self.db_config["max_overflow"],
                pool_pre_ping=True,
                echo=False,
            )

            self.Session = sessionmaker(bind=self.engine)
            self._test_connection()

            self.logger.info("Oracle database connection initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize Oracle connection: {e}")
            self.logger.info("Falling back to SQLite")
            self.use_oracle = False
            self._initialize_sqlite()

    def _initialize_sqlite(self):
        """Initialize SQLite database connection"""
        try:
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)

            self.connection = sqlite3.connect(self.db_file, check_same_thread=False)
            self.connection.execute("PRAGMA foreign_keys = ON")

            self.logger.info("SQLite database connection initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize SQLite connection: {e}")
            raise

    def _test_connection(self):
        """Test database connection"""
        try:
            if self.use_oracle:
                with self.engine.connect() as conn:
                    result = conn.execute(text("SELECT 1 FROM DUAL"))
                    result.fetchone()
            else:
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()

            self.logger.info("Database connection test successful")
        except Exception as e:
            self.logger.error(f"Database connection test failed: {e}")
            raise

    def _create_tables(self):
        """Create database tables"""
        try:
            if self.use_oracle:
                self._create_oracle_tables()
            else:
                self._create_sqlite_tables()

            self.logger.info("Database tables created successfully")

        except Exception as e:
            self.logger.error(f"Failed to create tables: {e}")
            raise

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
                classification VARCHAR2(50),
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_details CLOB
            )
            """,
            """
            CREATE TABLE quarantine_items (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                quarantine_id VARCHAR2(255) UNIQUE NOT NULL,
                original_path VARCHAR2(4000) NOT NULL,
                quarantine_path VARCHAR2(4000) NOT NULL,
                file_hash VARCHAR2(128),
                threat_name VARCHAR2(255),
                quarantine_reason CLOB,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restored_at TIMESTAMP,
                status VARCHAR2(20) DEFAULT 'QUARANTINED'
            )
            """,
        ]

        with self.engine.connect() as conn:
            for table_sql in tables:
                try:
                    conn.execute(text(table_sql))
                    conn.commit()
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        raise

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
                classification TEXT,
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
                threat_name TEXT,
                quarantine_reason TEXT,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restored_at TIMESTAMP,
                status TEXT DEFAULT 'QUARANTINED'
            )
            """,
        ]

        cursor = self.connection.cursor()
        for table_sql in tables:
            cursor.execute(table_sql)

        self.connection.commit()
        cursor.close()

    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup"""
        if self.use_oracle:
            conn = None
            try:
                conn = self.engine.connect()
                yield conn
            except Exception as e:
                if conn:
                    conn.rollback()
                self.logger.error(f"Database connection error: {e}")
                raise
            finally:
                if conn:
                    conn.close()
        else:
            with self._lock:
                yield self.connection

    def execute_query(self, query: str, params: Dict = None) -> List[Tuple]:
        """Execute SELECT query and return results"""
        try:
            if self.use_oracle:
                with self.get_connection() as conn:
                    if params:
                        result = conn.execute(text(query), params)
                    else:
                        result = conn.execute(text(query))
                    return result.fetchall()
            else:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    if params:
                        # Convert named parameters to positional for SQLite
                        sqlite_query = query
                        sqlite_params = []
                        for key, value in params.items():
                            sqlite_query = sqlite_query.replace(f":{key}", "?")
                            sqlite_params.append(value)
                        cursor.execute(sqlite_query, sqlite_params)
                    else:
                        cursor.execute(query)

                    results = cursor.fetchall()
                    cursor.close()
                    return results

        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise

    def execute_command(self, command: str, params: Dict = None) -> int:
        """Execute INSERT/UPDATE/DELETE command and return affected rows"""
        try:
            if self.use_oracle:
                with self.get_connection() as conn:
                    if params:
                        result = conn.execute(text(command), params)
                    else:
                        result = conn.execute(text(command))
                    conn.commit()
                    return result.rowcount
            else:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    if params:
                        # Convert named parameters to positional for SQLite
                        sqlite_command = command
                        sqlite_params = []
                        for key, value in params.items():
                            sqlite_command = sqlite_command.replace(f":{key}", "?")
                            sqlite_params.append(value)
                        cursor.execute(sqlite_command, sqlite_params)
                    else:
                        cursor.execute(command)

                    rowcount = cursor.rowcount
                    conn.commit()
                    cursor.close()
                    return rowcount

        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise

    def health_check(self) -> bool:
        """Perform database health check"""
        try:
            if self.use_oracle:
                with self.get_connection() as conn:
                    conn.execute(text("SELECT 1 FROM DUAL"))
            else:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    cursor.close()

            return True

        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return False

    def get_connection_info(self) -> Dict[str, Any]:
        """Get database connection information"""
        try:
            if self.use_oracle:
                with self.get_connection() as conn:
                    result = conn.execute(
                        text(
                            """
                        SELECT 
                            SYS_CONTEXT('USERENV', 'DB_NAME') as db_name,
                            SYS_CONTEXT('USERENV', 'SERVER_HOST') as server_host,
                            SYS_CONTEXT('USERENV', 'SESSION_USER') as session_user
                        FROM DUAL
                    """
                        )
                    )
                    row = result.fetchone()

                    return {
                        "database_type": "Oracle",
                        "database_name": row[0],
                        "server_host": row[1],
                        "session_user": row[2],
                        "pool_size": (
                            self.engine.pool.size()
                            if hasattr(self.engine, "pool")
                            else "N/A"
                        ),
                    }
            else:
                return {
                    "database_type": "SQLite",
                    "database_file": self.db_file,
                    "file_size": (
                        os.path.getsize(self.db_file)
                        if os.path.exists(self.db_file)
                        else 0
                    ),
                }

        except Exception as e:
            self.logger.error(f"Failed to get connection info: {e}")
            return {"error": str(e)}

    def close(self):
        """Close database connections"""
        try:
            if self.use_oracle and self.engine:
                self.engine.dispose()
            elif self.connection:
                self.connection.close()

            self.logger.info("Database connections closed")
        except Exception as e:
            self.logger.error(f"Error closing database connections: {e}")


# Global database manager instance
db_manager = DatabaseManager()
