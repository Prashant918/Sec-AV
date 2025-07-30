import os
import json
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from pathlib import Path
from typing import Dict, Any, Optional
import logging


class SecureConfig:
    """Advanced secure configuration management with encryption and validation"""

    def __init__(self):
        self.config_file = Path("config/secure_config.enc")
        self.key_file = Path("config/.key")
        self.salt_file = Path("config/.salt")
        self._cipher_suite = None
        self._config_data = {}
        self._initialize_security()

    def _initialize_security(self):
        """Initialize security components with proper key management"""
        try:
            os.makedirs("config", exist_ok=True)

            # Generate or load encryption key
            if not self.key_file.exists() or not self.salt_file.exists():
                self._generate_security_keys()

            self._load_cipher_suite()
            self._load_or_create_config()

        except Exception as e:
            logging.critical(f"Security initialization failed: {e}")
            raise SecurityError("Critical security initialization failure")

    def _generate_security_keys(self):
        """Generate cryptographically secure keys"""
        # Generate random salt
        salt = secrets.token_bytes(32)
        with open(self.salt_file, "wb") as f:
            f.write(salt)

        # Generate master key
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
        os.chmod(self.key_file, 0o600)
        os.chmod(self.salt_file, 0o600)

    def _load_cipher_suite(self):
        """Load encryption cipher suite"""
        try:
            with open(self.key_file, "rb") as f:
                key = f.read()
            self._cipher_suite = Fernet(key)
        except Exception as e:
            raise SecurityError(f"Failed to load encryption keys: {e}")

    def _load_or_create_config(self):
        """Load existing config or create default secure configuration"""
        if self.config_file.exists():
            self._load_encrypted_config()
        else:
            self._create_default_config()

    def _create_default_config(self):
        """Create default secure configuration"""
        default_config = {
            "security": {
                "max_file_size": 100 * 1024 * 1024,  # 100MB
                "allowed_extensions": [
                    ".exe",
                    ".dll",
                    ".pdf",
                    ".doc",
                    ".docx",
                    ".zip",
                    ".rar",
                ],
                "quarantine_encryption": True,
                "secure_delete": True,
                "integrity_check": True,
                "anti_tampering": True,
            },
            "detection": {
                "ml_threshold": 0.85,
                "heuristic_enabled": True,
                "behavioral_analysis": True,
                "zero_day_detection": True,
                "signature_updates": True,
                "cloud_intelligence": True,
            },
            "monitoring": {
                "real_time_enabled": True,
                "kernel_hooks": True,
                "process_monitoring": True,
                "network_monitoring": True,
                "file_integrity": True,
            },
            "logging": {
                "level": "INFO",
                "encrypted_logs": True,
                "audit_trail": True,
                "max_log_size": 50 * 1024 * 1024,  # 50MB
                "log_retention_days": 30,
            },
        }

        self._config_data = default_config
        self._save_encrypted_config()

    def _load_encrypted_config(self):
        """Load and decrypt configuration"""
        try:
            with open(self.config_file, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self._cipher_suite.decrypt(encrypted_data)
            self._config_data = json.loads(decrypted_data.decode())

        except Exception as e:
            logging.error(f"Failed to load encrypted config: {e}")
            self._create_default_config()

    def _save_encrypted_config(self):
        """Encrypt and save configuration"""
        try:
            config_json = json.dumps(self._config_data, indent=2)
            encrypted_data = self._cipher_suite.encrypt(config_json.encode())

            with open(self.config_file, "wb") as f:
                f.write(encrypted_data)

            os.chmod(self.config_file, 0o600)

        except Exception as e:
            logging.error(f"Failed to save encrypted config: {e}")
            raise SecurityError("Configuration save failed")

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key_path.split(".")
        value = self._config_data

        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key_path.split(".")
        config = self._config_data

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value
        self._save_encrypted_config()

    def validate_integrity(self) -> bool:
        """Validate configuration integrity"""
        try:
            # Check file permissions
            if oct(os.stat(self.config_file).st_mode)[-3:] != "600":
                return False

            # Verify encryption
            with open(self.config_file, "rb") as f:
                encrypted_data = f.read()

            self._cipher_suite.decrypt(encrypted_data)
            return True

        except Exception:
            return False


class SecurityError(Exception):
    """Custom security exception"""

    pass


# Global secure configuration instance
secure_config = SecureConfig()
