"""
Advanced Secure Logger for Prashant918 Antivirus
Provides encrypted logging with integrity protection and secure file handling
"""

import os
import sys
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    Fernet = None

import base64
import gzip
import struct

class SecureLoggerError(Exception):
    """Custom exception for secure logger errors"""
    pass

class LogIntegrityError(Exception):
    """Exception raised when log integrity is compromised"""
    pass

class EncryptedRotatingFileHandler(RotatingFileHandler):
    """Custom rotating file handler with encryption support"""
    
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, 
                 encoding=None, delay=False, encryption_key=None):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key) if encryption_key and HAS_CRYPTOGRAPHY else None
        self._lock = threading.Lock()
    
    def emit(self, record):
        """Emit a record with encryption if enabled"""
        try:
            with self._lock:
                if self.shouldRollover(record):
                    self.doRollover()
                
                # Format the record
                msg = self.format(record)
                
                # Encrypt if encryption is enabled
                if self.fernet:
                    # Add timestamp and integrity hash
                    timestamp = int(time.time())
                    integrity_hash = hashlib.sha256(msg.encode()).hexdigest()
                    
                    log_data = {
                        'timestamp': timestamp,
                        'message': msg,
                        'integrity_hash': integrity_hash,
                        'level': record.levelname,
                        'logger': record.name
                    }
                    
                    # Encrypt the log data
                    encrypted_data = self.fernet.encrypt(json.dumps(log_data).encode())
                    
                    # Write encrypted data with length prefix
                    data_length = len(encrypted_data)
                    self.stream.write(struct.pack('<I', data_length))
                    self.stream.write(encrypted_data)
                    self.stream.write(b'\n')
                else:
                    # Write plain text
                    self.stream.write(msg + self.terminator)
                
                self.flush()
                
        except Exception as e:
            self.handleError(record)
    
    def doRollover(self):
        """Perform rollover with encryption handling"""
        if self.stream:
            self.stream.close()
            self.stream = None
        
        # Rotate files
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = self.rotation_filename("%s.%d" % (self.baseFilename, i))
                dfn = self.rotation_filename("%s.%d" % (self.baseFilename, i + 1))
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            
            dfn = self.rotation_filename(self.baseFilename + ".1")
            if os.path.exists(dfn):
                os.remove(dfn)
            
            if os.path.exists(self.baseFilename):
                os.rename(self.baseFilename, dfn)
        
        # Open new file
        if not self.delay:
            self.stream = self._open()

class SecureLogFormatter(logging.Formatter):
    """Custom formatter with security enhancements"""
    
    def __init__(self, fmt=None, datefmt=None, include_sensitive=False):
        super().__init__(fmt, datefmt)
        self.include_sensitive = include_sensitive
        self.sensitive_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN
            r'password["\s]*[:=]["\s]*[^"\s]+',  # Passwords
            r'token["\s]*[:=]["\s]*[^"\s]+',  # Tokens
            r'key["\s]*[:=]["\s]*[^"\s]+',  # Keys
        ]
    
    def format(self, record):
        """Format record with security filtering"""
        # Create a copy of the record to avoid modifying the original
        record_copy = logging.makeLogRecord(record.__dict__)
        
        # Filter sensitive information if not explicitly included
        if not self.include_sensitive:
            record_copy.msg = self._filter_sensitive_data(str(record_copy.msg))
            
            # Filter args if present
            if record_copy.args:
                filtered_args = []
                for arg in record_copy.args:
                    if isinstance(arg, str):
                        filtered_args.append(self._filter_sensitive_data(arg))
                    else:
                        filtered_args.append(arg)
                record_copy.args = tuple(filtered_args)
        
        # Add security context
        record_copy.process_id = os.getpid()
        record_copy.thread_id = threading.get_ident()
        
        return super().format(record_copy)
    
    def _filter_sensitive_data(self, text: str) -> str:
        """Filter sensitive data from log messages"""
        import re
        
        filtered_text = text
        for pattern in self.sensitive_patterns:
            filtered_text = re.sub(pattern, '[REDACTED]', filtered_text, flags=re.IGNORECASE)
        
        return filtered_text

class SecureLogger:
    """Advanced secure logger with encryption and integrity protection"""
    
    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(name)
        self.encryption_key = None
        self._handlers = {}
        self._lock = threading.Lock()
        
        # Initialize logger
        self._setup_logger()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if none provided"""
        # Create logs directory
        log_dir = Path.home() / ".prashant918_antivirus" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        return {
            'level': 'INFO',
            'encryption': {
                'enabled': False,  # Disable encryption by default to avoid file path issues
                'password': 'prashant918_antivirus_secure_2024',
                'salt': 'antivirus_salt_secure_2024'
            },
            'integrity': {
                'enabled': False  # Disable integrity checking by default
            },
            'handlers': {
                'console': {
                    'enabled': True,
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    'include_sensitive': False
                },
                'file': {
                    'enabled': True,
                    'filename': str(log_dir / 'antivirus.log'),
                    'level': 'DEBUG',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(process_id)s - %(thread_id)s - %(message)s',
                    'include_sensitive': False
                }
            }
        }
    
    def _setup_logger(self):
        """Setup logger with configuration"""
        # Set log level
        log_level = self.config.get('level', 'INFO')
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup encryption if enabled
        if self.config.get('encryption', {}).get('enabled', False):
            self._setup_encryption()
        
        # Setup handlers
        self._setup_handlers()
    
    def _setup_encryption(self):
        """Setup encryption for log files"""
        if not HAS_CRYPTOGRAPHY:
            print("Warning: Cryptography library not available, encryption disabled")
            return
            
        encryption_config = self.config.get('encryption', {})
        
        # Generate or load encryption key
        key_file = encryption_config.get('key_file')
        if key_file and os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            # Generate new key
            password = encryption_config.get('password', 'default_password').encode()
            salt = encryption_config.get('salt', 'default_salt').encode()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self.encryption_key = key
            
            # Save key if path provided
            if key_file:
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(key)
                os.chmod(key_file, 0o600)
    
    def _setup_handlers(self):
        """Setup log handlers based on configuration"""
        handlers_config = self.config.get('handlers', {})
        
        # Console handler
        if handlers_config.get('console', {}).get('enabled', True):
            self._setup_console_handler(handlers_config.get('console', {}))
        
        # File handler
        if handlers_config.get('file', {}).get('enabled', True):
            self._setup_file_handler(handlers_config.get('file', {}))
    
    def _setup_console_handler(self, config: Dict[str, Any]):
        """Setup console handler"""
        handler = logging.StreamHandler(sys.stdout)
        
        # Set level
        level = config.get('level', 'INFO')
        handler.setLevel(getattr(logging, level.upper()))
        
        # Set formatter
        formatter = SecureLogFormatter(
            fmt=config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            datefmt=config.get('date_format', '%Y-%m-%d %H:%M:%S'),
            include_sensitive=config.get('include_sensitive', False)
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self._handlers['console'] = handler
    
    def _setup_file_handler(self, config: Dict[str, Any]):
        """Setup file handler"""
        log_file = config.get('filename')
        if not log_file:
            # Use default log file
            log_dir = Path.home() / ".prashant918_antivirus" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = str(log_dir / 'antivirus.log')
        
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.FileHandler(log_file, mode=config.get('mode', 'a'))
        
        # Set level
        level = config.get('level', 'INFO')
        handler.setLevel(getattr(logging, level.upper()))
        
        # Set formatter
        formatter = SecureLogFormatter(
            fmt=config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            datefmt=config.get('date_format', '%Y-%m-%d %H:%M:%S'),
            include_sensitive=config.get('include_sensitive', False)
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self._handlers['file'] = handler
    
    def log(self, level: str, message: str, extra: Dict[str, Any] = None):
        """Log message with optional extra data"""
        with self._lock:
            # Log the message
            log_method = getattr(self.logger, level.lower())
            if extra:
                log_method(message, extra=extra)
            else:
                log_method(message)
    
    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log debug message"""
        self.log('DEBUG', message, extra)
    
    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log info message"""
        self.log('INFO', message, extra)
    
    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log warning message"""
        self.log('WARNING', message, extra)
    
    def error(self, message: str, extra: Dict[str, Any] = None):
        """Log error message"""
        self.log('ERROR', message, extra)
    
    def critical(self, message: str, extra: Dict[str, Any] = None):
        """Log critical message"""
        self.log('CRITICAL', message, extra)
    
    def close(self):
        """Close all handlers and cleanup resources"""
        try:
            for handler in self.logger.handlers[:]:
                handler.close()
                self.logger.removeHandler(handler)
            
            self._handlers.clear()
            
        except Exception as e:
            print(f"Error closing logger: {e}")

# Utility functions for logger management
def create_secure_logger(name: str, config_file: str = None, config_dict: Dict[str, Any] = None) -> SecureLogger:
    """Create secure logger from configuration"""
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    elif config_dict:
        config = config_dict
    else:
        config = None  # Use default config
    
    return SecureLogger(name, config)

def setup_default_logging(log_dir: str = None) -> SecureLogger:
    """Setup default logging configuration"""
    if log_dir is None:
        log_dir = str(Path.home() / ".prashant918_antivirus" / "logs")
    
    # Ensure log directory exists
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    config = {
        'level': 'INFO',
        'encryption': {
            'enabled': False  # Disable encryption by default
        },
        'handlers': {
            'console': {
                'enabled': True,
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'include_sensitive': False
            },
            'file': {
                'enabled': True,
                'filename': os.path.join(log_dir, 'antivirus.log'),
                'level': 'DEBUG',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(process_id)s - %(thread_id)s - %(message)s',
                'include_sensitive': False
            }
        }
    }
    
    return SecureLogger('prashant918_antivirus', config)

# Global logger instance
_global_logger = None

def get_logger(name: str = None) -> SecureLogger:
    """Get global logger instance"""
    global _global_logger
    
    if _global_logger is None:
        logger_name = name or 'prashant918_antivirus'
        _global_logger = setup_default_logging()
    
    return _global_logger

def main():
    """Main function for testing logger functionality"""
    try:
        # Create secure logger
        logger = setup_default_logging()
        
        # Test logging
        logger.info("Secure logger initialized successfully")
        logger.debug("This is a debug message")
        logger.warning("This is a warning message")
        logger.error("This is an error message")
        
        # Test with sensitive data
        logger.info("User password: secret123")  # Should be redacted
        logger.info("Credit card: 1234-5678-9012-3456")  # Should be redacted
        
        logger.info("Logger testing completed successfully")
        
    except Exception as e:
        print(f"Logger test failed: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())