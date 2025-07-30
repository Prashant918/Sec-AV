"""
Prashant918 Advanced Antivirus - Enhanced Configuration Management
Secure configuration with encryption, validation, and cross-platform support
"""
import os
import sys
import json
import yaml
import hashlib
import secrets
import base64
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Error handling
try:
    from .exceptions import AntivirusError, ConfigurationError
except ImportError:
    class AntivirusError(Exception): pass
    class ConfigurationError(AntivirusError): pass

class SecureConfig:
    """Enhanced secure configuration management with encryption and validation"""
    
    def __init__(self, config_dir: Optional[str] = None):
        # Set up configuration directory
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Use user's home directory for configuration
            home_dir = Path.home()
            self.config_dir = home_dir / ".prashant918_antivirus" / "config"
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration files
        self.config_file = self.config_dir / "secure_config.enc"
        self.key_file = self.config_dir / "config.key"
        self.salt_file = self.config_dir / "config.salt"
        self.backup_file = self.config_dir / "config_backup.enc"
        
        # Internal state
        self._cipher_suite = None
        self._config_data = {}
        self._config_lock = False
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize security and load configuration
        self._initialize_security()
    
    def _initialize_security(self):
        """Initialize security components with proper key management"""
        try:
            # Ensure config directory has secure permissions
            self._set_secure_permissions()
            
            # Generate or load encryption key
            if not self.key_file.exists() or not self.salt_file.exists():
                self._generate_security_keys()
            
            self._load_cipher_suite()
            self._load_or_create_config()
            
        except Exception as e:
            self.logger.critical(f"Security initialization failed: {e}")
            # Fall back to unencrypted configuration
            self._fallback_to_plain_config()
    
    def _set_secure_permissions(self):
        """Set secure permissions on configuration directory"""
        try:
            if hasattr(os, 'chmod') and sys.platform != 'win32':
                os.chmod(self.config_dir, 0o700)
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Could not set secure permissions: {e}")
    
    def _generate_security_keys(self):
        """Generate cryptographically secure keys"""
        try:
            # Generate random salt
            salt = secrets.token_bytes(32)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            
            # Generate master key using PBKDF2
            password = secrets.token_urlsafe(64).encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            with open(self.key_file, "wb") as f:
                f.write(key)
            
            # Set restrictive permissions
            if hasattr(os, 'chmod') and sys.platform != 'win32':
                os.chmod(self.key_file, 0o600)
                os.chmod(self.salt_file, 0o600)
            
            self.logger.info("Security keys generated successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to generate security keys: {e}")
            raise ConfigurationError("Critical security key generation failure")
    
    def _load_cipher_suite(self):
        """Load cipher suite for encryption/decryption"""
        try:
            with open(self.key_file, "rb") as f:
                key = f.read()
            
            self._cipher_suite = Fernet(key)
            
        except Exception as e:
            self.logger.error(f"Failed to load cipher suite: {e}")
            raise ConfigurationError("Critical cipher suite loading failure")
    
    def _load_or_create_config(self):
        """Load existing configuration or create default"""
        try:
            if self.config_file.exists():
                self._load_encrypted_config()
            else:
                self._create_default_config()
                
        except Exception as e:
            self.logger.error(f"Configuration loading failed: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration"""
        try:
            self._config_data = {
                "security": {
                    "max_file_size": 100 * 1024 * 1024,  # 100MB
                    "allowed_extensions": [
                        ".exe", ".dll", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                        ".zip", ".rar", ".7z", ".tar", ".gz", ".jpg", ".png", ".gif"
                    ],
                    "quarantine_encryption": True,
                    "secure_delete": True,
                    "permission_check": True
                },
                "detection": {
                    "ml_threshold": 0.85,
                    "heuristic_threshold": 0.75,
                    "behavioral_threshold": 0.80,
                    "signature_threshold": 0.90,
                    "enable_ml": True,
                    "enable_heuristics": True,
                    "enable_behavioral": True,
                    "enable_signatures": True,
                    "detection_weights": {
                        "ml": 0.35,
                        "heuristic": 0.20,
                        "behavioral": 0.25,
                        "signature": 0.20
                    }
                },
                "monitoring": {
                    "enabled": True,
                    "paths": [
                        str(Path.home() / "Downloads"),
                        str(Path.home() / "Desktop"),
                        str(Path.home() / "Documents")
                    ],
                    "extensions": [".exe", ".scr", ".bat", ".cmd", ".com", ".pif"],
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
                    "type": "sqlite",  # sqlite or oracle
                    "sqlite_path": str(self.config_dir.parent / "data" / "antivirus.db"),
                    "oracle": {
                        "host": "localhost",
                        "port": 1521,
                        "service_name": "XEPDB1",
                        "username": "antivirus",
                        "password": "",
                        "pool_size": 5,
                        "max_overflow": 10
                    }
                },
                "cloud": {
                    "enabled": True,
                    "virustotal_api_key": "",
                    "malwarebazaar_api_key": "",
                    "hybrid_analysis_api_key": "",
                    "update_interval": 3600,  # 1 hour
                    "cache_ttl": 86400,  # 24 hours
                    "max_file_size": 32 * 1024 * 1024  # 32MB
                },
                "performance": {
                    "max_threads": min(8, os.cpu_count() or 1),
                    "max_processes": min(4, os.cpu_count() or 1),
                    "cache_size": 1000,
                    "cache_ttl": 3600,
                    "memory_limit": 512 * 1024 * 1024,  # 512MB
                    "scan_timeout": 300  # 5 minutes
                },
                "quarantine": {
                    "enabled": True,
                    "path": str(self.config_dir.parent / "quarantine"),
                    "max_size": 1024 * 1024 * 1024,  # 1GB
                    "retention_days": 30,
                    "encrypt_files": True,
                    "compress_files": True
                },
                "updates": {
                    "auto_update": True,
                    "update_interval": 3600,  # 1 hour
                    "signature_sources": [
                        "https://api.virustotal.com/",
                        "https://mb-api.abuse.ch/",
                        "https://www.hybrid-analysis.com/api/"
                    ],
                    "backup_signatures": True
                }
            }
            
            self._save_encrypted_config()
            self.logger.info("Default configuration created")
            
        except Exception as e:
            self.logger.error(f"Failed to create default configuration: {e}")
            raise ConfigurationError("Critical default configuration creation failure")
    
    def _load_encrypted_config(self):
        """Load encrypted configuration from file"""
        try:
            with open(self.config_file, "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = self._cipher_suite.decrypt(encrypted_data)
            self._config_data = json.loads(decrypted_data.decode())
            
            self.logger.debug("Encrypted configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load encrypted configuration: {e}")
            # Try to load from backup
            if self.backup_file.exists():
                try:
                    with open(self.backup_file, "rb") as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = self._cipher_suite.decrypt(encrypted_data)
                    self._config_data = json.loads(decrypted_data.decode())
                    
                    self.logger.info("Configuration restored from backup")
                    return
                except Exception as backup_error:
                    self.logger.error(f"Backup restoration failed: {backup_error}")
            
            # Fall back to default configuration
            self._create_default_config()
    
    def _save_encrypted_config(self):
        """Save configuration to encrypted file"""
        try:
            # Create backup of current config
            if self.config_file.exists():
                try:
                    with open(self.config_file, "rb") as src, open(self.backup_file, "wb") as dst:
                        dst.write(src.read())
                except Exception as e:
                    self.logger.warning(f"Failed to create config backup: {e}")
            
            # Save new configuration
            json_data = json.dumps(self._config_data, indent=2).encode()
            encrypted_data = self._cipher_suite.encrypt(json_data)
            
            with open(self.config_file, "wb") as f:
                f.write(encrypted_data)
            
            # Set secure permissions
            if hasattr(os, 'chmod') and sys.platform != 'win32':
                os.chmod(self.config_file, 0o600)
            
            self.logger.debug("Configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise ConfigurationError("Critical configuration save failure")
    
    def _fallback_to_plain_config(self):
        """Fallback to plain text configuration if encryption fails"""
        try:
            self.logger.warning("Falling back to plain text configuration")
            
            plain_config_file = self.config_dir / "config.json"
            
            if plain_config_file.exists():
                with open(plain_config_file, "r") as f:
                    self._config_data = json.load(f)
            else:
                self._create_default_config()
                # Save as plain text
                with open(plain_config_file, "w") as f:
                    json.dump(self._config_data, f, indent=2)
            
            # Disable encryption for this session
            self._cipher_suite = None
            
        except Exception as e:
            self.logger.error(f"Fallback configuration failed: {e}")
            # Use minimal default configuration
            self._config_data = {
                "security": {"max_file_size": 100 * 1024 * 1024},
                "detection": {"ml_threshold": 0.85},
                "monitoring": {"enabled": True, "paths": [str(Path.home())]},
                "logging": {"level": "INFO"}
            }
    
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
            
        except Exception as e:
            self.logger.error(f"Failed to get config value for key '{key}': {e}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value using dot notation"""
        try:
            if self._config_lock:
                self.logger.warning("Configuration is locked")
                return False
            
            keys = key.split('.')
            config = self._config_data
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            
            # Save configuration
            if self._cipher_suite:
                self._save_encrypted_config()
            else:
                # Save as plain text
                plain_config_file = self.config_dir / "config.json"
                with open(plain_config_file, "w") as f:
                    json.dump(self._config_data, f, indent=2)
            
            self.logger.debug(f"Configuration updated: {key} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set config value for key '{key}': {e}")
            return False
    
    def validate_integrity(self) -> bool:
        """Validate configuration integrity"""
        try:
            # Check file permissions
            if hasattr(os, 'stat') and sys.platform != 'win32':
                stat_info = os.stat(self.config_file)
                if stat_info.st_mode & 0o077:  # Check if readable by others
                    self.logger.warning("Configuration file has insecure permissions")
                    return False
            
            # Try to decrypt configuration
            if self._cipher_suite and self.config_file.exists():
                with open(self.config_file, "rb") as f:
                    encrypted_data = f.read()
                
                try:
                    self._cipher_suite.decrypt(encrypted_data)
                    return True
                except Exception:
                    self.logger.error("Configuration decryption failed")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Integrity validation failed: {e}")
            return False
    
    def export_config(self, export_path: str, include_sensitive: bool = False) -> bool:
        """Export configuration to file"""
        try:
            export_data = self._config_data.copy()
            
            if not include_sensitive:
                # Remove sensitive information
                sensitive_keys = [
                    'cloud.virustotal_api_key',
                    'cloud.malwarebazaar_api_key', 
                    'cloud.hybrid_analysis_api_key',
                    'database.oracle.password'
                ]
                
                for key in sensitive_keys:
                    keys = key.split('.')
                    data = export_data
                    for k in keys[:-1]:
                        if k in data:
                            data = data[k]
                        else:
                            break
                    else:
                        if keys[-1] in data:
                            data[keys[-1]] = "***REDACTED***"
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Configuration exported to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration export failed: {e}")
            return False
    
    def import_config(self, import_path: str) -> bool:
        """Import configuration from file"""
        try:
            with open(import_path, 'r') as f:
                imported_data = json.load(f)
            
            # Validate imported configuration
            if not isinstance(imported_data, dict):
                raise ValueError("Invalid configuration format")
            
            # Merge with current configuration
            self._merge_config(self._config_data, imported_data)
            
            # Save updated configuration
            if self._cipher_suite:
                self._save_encrypted_config()
            else:
                plain_config_file = self.config_dir / "config.json"
                with open(plain_config_file, "w") as f:
                    json.dump(self._config_data, f, indent=2)
            
            self.logger.info(f"Configuration imported from {import_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration import failed: {e}")
            return False
    
    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to default values"""
        try:
            self.logger.info("Resetting configuration to defaults")
            self._create_default_config()
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to reset configuration: {e}")
            return False
    
    def lock_config(self):
        """Lock configuration to prevent modifications"""
        self._config_lock = True
        self.logger.info("Configuration locked")
    
    def unlock_config(self):
        """Unlock configuration to allow modifications"""
        self._config_lock = False
        self.logger.info("Configuration unlocked")
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration data"""
        return self._config_data.copy()
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get configuration system information"""
        return {
            'config_dir': str(self.config_dir),
            'encrypted': self._cipher_suite is not None,
            'locked': self._config_lock,
            'files_exist': {
                'config': self.config_file.exists(),
                'key': self.key_file.exists(),
                'salt': self.salt_file.exists(),
                'backup': self.backup_file.exists()
            },
            'integrity_valid': self.validate_integrity()
        }

# Global configuration instance
secure_config = SecureConfig()

# Backward compatibility
class SecurityError(ConfigurationError):
    """Backward compatibility alias"""
    pass
