import logging
import os
import json
import time
import hashlib
import threading
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from typing import Dict, Any, Optional
from .config import secure_config

class SecureLogger:
    """Advanced secure logging with encryption and integrity protection"""
    
    def __init__(self, component_name: str):
        self.component_name = component_name
        self.log_dir = "logs"
        self.encrypted_logs = secure_config.get("logging.encrypted_logs", True)
        self.max_log_size = secure_config.get("logging.max_log_size", 50 * 1024 * 1024)
        self.retention_days = secure_config.get("logging.log_retention_days", 30)
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Initialize logging
        self._initialize_logging()
        
        # Initialize encryption if enabled
        if self.encrypted_logs:
            self._initialize_encryption()
    
    def _initialize_logging(self):
        """Initialize secure logging configuration"""
        try:
            # Create logs directory
            os.makedirs(self.log_dir, exist_ok=True)
            
            # Set restrictive permissions
            os.chmod(self.log_dir, 0o700)
            
            # Configure logger
            self.logger = logging.getLogger(f"SecureAV.{self.component_name}")
            self.logger.setLevel(getattr(logging, secure_config.get("logging.level", "INFO")))
            
            # Remove existing handlers
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
            
            # Create secure file handler
            log_file = os.path.join(self.log_dir, f"{self.component_name.lower()}.log")
            handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            
            # Set restrictive permissions on log file
            if os.path.exists(log_file):
                os.chmod(log_file, 0o600)
            
            # Create secure formatter
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
            self.logger.propagate = False
            
        except Exception as e:
            print(f"Failed to initialize secure logging: {e}")
            raise
    
    def _initialize_encryption(self):
        """Initialize log encryption"""
        try:
            key_file = os.path.join(self.log_dir, ".log_key")
            
            if not os.path.exists(key_file):
                # Generate new encryption key
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                os.chmod(key_file, 0o600)
            else:
                # Load existing key
                with open(key_file, 'rb') as f:
                    key = f.read()
            
            self.cipher_suite = Fernet(key)
            
        except Exception as e:
            print(f"Failed to initialize log encryption: {e}")
            self.encrypted_logs = False
    
    def _log_with_integrity(self, level: str, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log message with integrity protection"""
        try:
            with self.lock:
                # Create log entry
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "component": self.component_name,
                    "level": level,
                    "message": message,
                    "extra": extra_data or {}
                }
                
                # Add integrity hash
                entry_json = json.dumps(log_entry, sort_keys=True)
                integrity_hash = hashlib.sha256(entry_json.encode()).hexdigest()
                log_entry["integrity_hash"] = integrity_hash
                
                # Log through standard logger
                getattr(self.logger, level.lower())(json.dumps(log_entry))
                
                # Encrypted audit log
                if self.encrypted_logs:
                    self._write_encrypted_audit_log(log_entry)
                
                # Check log rotation
                self._check_log_rotation()
                
        except Exception as e:
            # Fallback logging
            print(f"Secure logging failed: {e}")
            self.logger.error(f"Secure logging failed: {e}")
    
    def _write_encrypted_audit_log(self, log_entry: Dict[str, Any]):
        """Write encrypted audit log"""
        try:
            audit_file = os.path.join(self.log_dir, "audit.enc")
            
            # Encrypt log entry
            entry_json = json.dumps(log_entry)
            encrypted_entry = self.cipher_suite.encrypt(entry_json.encode())
            
            # Append to audit file
            with open(audit_file, 'ab') as f:
                f.write(encrypted_entry + b'\n')
            
            # Set permissions
            os.chmod(audit_file, 0o600)
            
        except Exception as e:
            self.logger.error(f"Failed to write encrypted audit log: {e}")
    
    def _check_log_rotation(self):
        """Check and perform log rotation if needed"""
        try:
            log_file = os.path.join(self.log_dir, f"{self.component_name.lower()}.log")
            
            if os.path.exists(log_file) and os.path.getsize(log_file) > self.max_log_size:
                # Rotate log file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated_file = f"{log_file}.{timestamp}"
                os.rename(log_file, rotated_file)
                
                # Compress rotated file if possible
                try:
                    import gzip
                    with open(rotated_file, 'rb') as f_in:
                        with gzip.open(f"{rotated_file}.gz", 'wb') as f_out:
                            f_out.writelines(f_in)
                    os.remove(rotated_file)
                except ImportError:
                    pass
                
                # Reinitialize handler
                self._initialize_logging()
            
            # Clean old logs
            self._cleanup_old_logs()
            
        except Exception as e:
            self.logger.error(f"Log rotation failed: {e}")
    
    def _cleanup_old_logs(self):
        """Clean up old log files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            for filename in os.listdir(self.log_dir):
                file_path = os.path.join(self.log_dir, filename)
                
                if os.path.isfile(file_path):
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_time < cutoff_date and not filename.startswith('.'):
                        os.remove(file_path)
                        
        except Exception as e:
            self.logger.error(f"Log cleanup failed: {e}")
    
    def info(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log info message"""
        self._log_with_integrity("INFO", message, extra_data)
    
    def warning(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        self._log_with_integrity("WARNING", message, extra_data)
    
    def error(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log error message"""
        self._log_with_integrity("ERROR", message, extra_data)
    
    def critical(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log critical message"""
        self._log_with_integrity("CRITICAL", message, extra_data)
    
    def debug(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log debug message"""
        self._log_with_integrity("DEBUG", message, extra_data)
    
    def security_event(self, event_type: str, description: str, 
                      severity: str = "HIGH", extra_data: Optional[Dict[str, Any]] = None):
        """Log security event"""
        security_data = {
            "event_type": event_type,
            "severity": severity,
            "description": description,
            **(extra_data or {})
        }
        
        self._log_with_integrity("CRITICAL", f"SECURITY_EVENT: {event_type}", security_data)
    
    def read_encrypted_audit_logs(self, start_time: Optional[datetime] = None, 
                                 end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Read and decrypt audit logs"""
        try:
            if not self.encrypted_logs:
                return []
            
            audit_file = os.path.join(self.log_dir, "audit.enc")
            if not os.path.exists(audit_file):
                return []
            
            logs = []
            with open(audit_file, 'rb') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            decrypted_data = self.cipher_suite.decrypt(line)
                            log_entry = json.loads(decrypted_data.decode())
                            
                            # Filter by time range if specified
                            if start_time or end_time:
                                log_time = datetime.fromisoformat(log_entry["timestamp"])
                                if start_time and log_time < start_time:
                                    continue
                                if end_time and log_time > end_time:
                                    continue
                            
                            logs.append(log_entry)
                            
                        except Exception as e:
                            self.logger.error(f"Failed to decrypt audit log entry: {e}")
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Failed to read encrypted audit logs: {e}")
            return []