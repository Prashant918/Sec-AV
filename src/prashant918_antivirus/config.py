"""
Secure Configuration Manager - Encrypted configuration with validation
"""
import os
import json
import secrets
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Union
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class SecureConfig:
    """
    Secure configuration manager with encryption and validation
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / ".prashant918_antivirus" / "config"
        self.config_file = self.config_dir / "secure_config.enc"
        self.key_file = self.config_dir / "config.key"
        self.salt_file = self.config_dir / "config.salt"
        self.backup_file = self.config_dir / "config_backup.enc"
        
        # Configuration data
        self._config_data = {}
        self.cipher_suite = None
        self.encryption_enabled = HAS_CRYPTOGRAPHY
        self._locked = False
        
        # Initialize
        self._initialize_security()
    
    def _initialize_security(self):
        """Initialize security components"""
        try:
            # Create config directory
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Set secure permissions
            if os.name != 'nt':
                os.chmod(self.config_dir, 0o700)
            
            # Generate or load keys
            if self.encryption_enabled:
                self._generate_security_keys()
                self._load_cipher_suite()
            
            # Load or create configuration
            self._load_or_create_config()
            
        except Exception as e:
            print(f"Warning: Failed to initialize secure config: {e}")
            self.encryption_enabled = False
            self._fallback_to_plain_config()
    
    def _generate_security_keys(self):
        """Generate encryption keys if they don't exist"""
        try:
            if not self.salt_file.exists():
                # Generate salt
                salt = secrets.token_bytes(32)
                with open(self.salt_file, 'wb') as f:
                    f.write(salt)
                
                if os.name != 'nt':
                    os.chmod(self.salt_file, 0o600)
            
            if not self.key_file.exists():
                # Generate key
                with open(self.salt_file, 'rb') as f:
                    salt = f.read()
                
                password = secrets.token_bytes(32)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                
                if os.name != 'nt':
                    os.chmod(self.key_file, 0o600)
                    
        except Exception as e:
            print(f"Warning: Failed to generate security keys: {e}")
            self.encryption_enabled = False
    
    def _load_cipher_suite(self):
        """Load the cipher suite for encryption/decryption"""
        try:
            with open(self.key_file, 'rb') as f:
                key = f.read()
            self.cipher_suite = Fernet(key)
        except Exception as e:
            print(f"Warning: Failed to load cipher suite: {e}")
            self.encryption_enabled = False
    
    def _load_or_create_config(self):
        """Load existing config or create default"""
        if self.config_file.exists():
            self._load_encrypted_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration"""
        self._config_data = {
            "security": {
                "max_file_size": 100 * 1024 * 1024,  # 100MB
                "allowed_extensions": [
                    ".exe", ".dll", ".sys", ".com", ".scr", ".pif", ".bat", ".cmd",
                    ".vbs", ".js", ".jar", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                    ".ppt", ".pptx", ".zip", ".rar", ".7z", ".tar", ".gz"
                ],
                "quarantine_encryption": True,
                "secure_delete": True,
                "permission_check": True
            },
            "detection": {
                "ml_threshold": 0.7,
                "heuristic_threshold": 0.6,
                "behavioral_threshold": 0.8,
                "signature_threshold": 0.9,
                "enable_ml": True,
                "enable_heuristics": True,
                "enable_behavioral": True,
                "enable_signatures": True,
                "detection_weights": {
                    "ml": 0.3,
                    "heuristic": 0.2,
                    "behavioral": 0.3,
                    "signature": 0.2
                }
            },
            "monitoring": {
                "enabled": True,
                "paths": [
                    str(Path.home() / "Downloads"),
                    str(Path.home() / "Desktop"),
                    str(Path.home() / "Documents")
                ],
                "extensions": [".exe", ".dll", ".pdf", ".doc", ".docx"],
                "real_time_scan": True,
                "monitor_usb": True,
                "monitor_network": True,
                "scan_archives": True
            },
            "logging": {
                "level": "INFO",
                "max_file_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5,
                "log_to_file": True,
                "log_to_console": True,
                "secure_logging": True
            },
            "database": {
                "type": "sqlite",
                "sqlite_path": str(Path.home() / ".prashant918_antivirus" / "antivirus.db")
            },
            "cloud": {
                "enabled": True,
                "update_interval": 3600,  # 1 hour
                "cache_ttl": 1800,  # 30 minutes
                "max_file_size": 50 * 1024 * 1024  # 50MB
            },
            "performance": {
                "max_threads": 4,
                "max_processes": 2,
                "cache_size": 1000,
                "cache_ttl": 300,  # 5 minutes
                "memory_limit": 512 * 1024 * 1024,  # 512MB
                "scan_timeout": 60  # 60 seconds
            },
            "quarantine": {
                "directory": str(Path.home() / ".prashant918_antivirus" / "quarantine"),
                "max_size": 1024 * 1024 * 1024,  # 1GB
                "retention_days": 30,
                "encryption_enabled": True,
                "secure_delete": True
            },
            "updates": {
                "auto_update": True,
                "check_interval": 86400,  # 24 hours
                "backup_before_update": True
            }
        }
        
        self._save_encrypted_config()
    
    def _load_encrypted_config(self):
        """Load encrypted configuration"""
        try:
            if self.encryption_enabled and self.cipher_suite:
                with open(self.config_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                self._config_data = json.loads(decrypted_data.decode())
            else:
                self._fallback_to_plain_config()
                
        except Exception as e:
            print(f"Warning: Failed to load encrypted config: {e}")
            self._fallback_to_plain_config()
    
    def _save_encrypted_config(self):
        """Save configuration in encrypted format"""
        try:
            if self._locked:
                raise RuntimeError("Configuration is locked")
            
            # Backup existing config
            if self.config_file.exists():
                self.config_file.rename(self.backup_file)
            
            if self.encryption_enabled and self.cipher_suite:
                config_json = json.dumps(self._config_data, indent=2)
                encrypted_data = self.cipher_suite.encrypt(config_json.encode())
                
                with open(self.config_file, 'wb') as f:
                    f.write(encrypted_data)
                
                if os.name != 'nt':
                    os.chmod(self.config_file, 0o600)
            else:
                self._save_plain_config()
                
        except Exception as e:
            print(f"Warning: Failed to save encrypted config: {e}")
            self._save_plain_config()
    
    def _fallback_to_plain_config(self):
        """Fallback to plain text configuration"""
        plain_config_file = self.config_dir / "config.json"
        
        try:
            if plain_config_file.exists():
                with open(plain_config_file, 'r') as f:
                    self._config_data = json.load(f)
            else:
                self._create_default_config()
                self._save_plain_config()
        except Exception as e:
            print(f"Warning: Failed to load plain config: {e}")
            self._create_default_config()
    
    def _save_plain_config(self):
        """Save configuration in plain text format"""
        plain_config_file = self.config_dir / "config.json"
        
        try:
            with open(plain_config_file, 'w') as f:
                json.dump(self._config_data, f, indent=2)
            
            if os.name != 'nt':
                os.chmod(plain_config_file, 0o600)
                
        except Exception as e:
            print(f"Error: Failed to save plain config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        try:
            keys = key.split('.')
            value = self._config_data
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        if self._locked:
            raise RuntimeError("Configuration is locked")
        
        try:
            keys = key.split('.')
            config = self._config_data
            
            # Navigate to the parent dictionary
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            
            # Save the updated configuration
            self._save_encrypted_config()
            
        except Exception as e:
            print(f"Error: Failed to set config value: {e}")
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration data"""
        return self._config_data.copy()
    
    def validate_integrity(self) -> bool:
        """Validate configuration integrity"""
        try:
            # Check file permissions
            if self.config_file.exists():
                stat = self.config_file.stat()
                if os.name != 'nt' and (stat.st_mode & 0o077) != 0:
                    return False
            
            # Try to decrypt config
            if self.encryption_enabled and self.cipher_suite:
                self._load_encrypted_config()
            
            return True
            
        except Exception:
            return False
    
    def lock_config(self):
        """Lock configuration to prevent modifications"""
        self._locked = True
    
    def unlock_config(self):
        """Unlock configuration to allow modifications"""
        self._locked = False
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        if self._locked:
            raise RuntimeError("Configuration is locked")
        
        self._create_default_config()
    
    def export_config(self, export_path: str, redact_sensitive: bool = True) -> bool:
        """Export configuration to file"""
        try:
            config_copy = self._config_data.copy()
            
            if redact_sensitive:
                # Redact sensitive information
                sensitive_keys = ['api_key', 'password', 'secret', 'token']
                self._redact_sensitive_data(config_copy, sensitive_keys)
            
            with open(export_path, 'w') as f:
                json.dump(config_copy, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error: Failed to export config: {e}")
            return False
    
    def _redact_sensitive_data(self, data: Dict, sensitive_keys: list):
        """Recursively redact sensitive data"""
        for key, value in data.items():
            if isinstance(value, dict):
                self._redact_sensitive_data(value, sensitive_keys)
            elif any(sensitive in key.lower() for sensitive in sensitive_keys):
                data[key] = "[REDACTED]"
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get configuration system information"""
        return {
            'config_dir': str(self.config_dir),
            'config_file': str(self.config_file),
            'encryption_enabled': self.encryption_enabled,
            'locked': self._locked,
            'file_exists': self.config_file.exists(),
            'integrity_valid': self.validate_integrity()
        }

# Global configuration instance
secure_config = SecureConfig()