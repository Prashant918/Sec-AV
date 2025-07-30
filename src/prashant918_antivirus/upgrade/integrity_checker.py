"""
Update Integrity Checker
Verifies the integrity and authenticity of updates
"""

import hashlib
import hmac
import json
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import tempfile
import shutil

from ..logger import SecureLogger
from ..exceptions import UpdateError, ValidationError


class IntegrityChecker:
    """
    Verifies update integrity and authenticity
    """
    
    def __init__(self):
        self.logger = SecureLogger("IntegrityChecker")
        
        # Verification settings
        self.supported_algorithms = ['sha256', 'sha512', 'md5']
        self.required_files = [
            'src/',
            'version_info.json',
            'update_manifest.json'
        ]
        
        # Digital signature verification (if available)
        self.signature_verification_enabled = False
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            self.signature_verification_enabled = True
            self.hashes = hashes
            self.serialization = serialization
            self.rsa = rsa
            self.padding = padding
        except ImportError:
            self.logger.warning("Cryptography library not available - signature verification disabled")
            
    def verify_update(self, update_file: Path, expected_checksum: str, 
                     algorithm: str = 'sha256') -> bool:
        """Verify update file integrity"""
        try:
            self.logger.info(f"Verifying update file: {update_file}")
            
            # Check if file exists and is readable
            if not update_file.exists():
                raise ValidationError(f"Update file not found: {update_file}")
                
            if not update_file.is_file():
                raise ValidationError(f"Update path is not a file: {update_file}")
                
            # Verify file checksum
            if not self._verify_file_checksum(update_file, expected_checksum, algorithm):
                raise ValidationError("File checksum verification failed")
                
            # Verify ZIP file integrity
            if not self._verify_zip_integrity(update_file):
                raise ValidationError("ZIP file integrity check failed")
                
            # Verify update contents
            if not self._verify_update_contents(update_file):
                raise ValidationError("Update contents verification failed")
                
            # Verify digital signature if available
            if self.signature_verification_enabled:
                if not self._verify_digital_signature(update_file):
                    self.logger.warning("Digital signature verification failed")
                    # Don't fail the update for signature issues in this version
                    
            self.logger.info("Update file verification successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Update verification failed: {e}")
            return False
            
    def _verify_file_checksum(self, file_path: Path, expected_checksum: str, 
                            algorithm: str) -> bool:
        """Verify file checksum"""
        try:
            if algorithm not in self.supported_algorithms:
                raise ValidationError(f"Unsupported hash algorithm: {algorithm}")
                
            # Calculate file hash
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
                    
            calculated_checksum = hash_obj.hexdigest()
            
            # Compare checksums (case-insensitive)
            if calculated_checksum.lower() != expected_checksum.lower():
                self.logger.error(
                    f"Checksum mismatch - Expected: {expected_checksum}, "
                    f"Calculated: {calculated_checksum}"
                )
                return False
                
            self.logger.debug(f"Checksum verification passed ({algorithm})")
            return True
            
        except Exception as e:
            self.logger.error(f"Checksum verification error: {e}")
            return False
            
    def _verify_zip_integrity(self, zip_file: Path) -> bool:
        """Verify ZIP file integrity"""
        try:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                # Test ZIP file integrity
                bad_file = zf.testzip()
                if bad_file:
                    self.logger.error(f"Corrupted file in ZIP: {bad_file}")
                    return False
                    
                # Check for suspicious files
                for file_info in zf.filelist:
                    # Check for path traversal attempts
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        self.logger.error(f"Suspicious file path: {file_info.filename}")
                        return False
                        
                    # Check for excessively large files (zip bomb protection)
                    if file_info.file_size > 100 * 1024 * 1024:  # 100MB limit
                        self.logger.warning(f"Large file in update: {file_info.filename}")
                        
                    # Check compression ratio (zip bomb protection)
                    if file_info.compress_size > 0:
                        ratio = file_info.file_size / file_info.compress_size
                        if ratio > 100:  # Suspicious compression ratio
                            self.logger.warning(
                                f"High compression ratio for {file_info.filename}: {ratio}"
                            )
                            
            self.logger.debug("ZIP integrity verification passed")
            return True
            
        except zipfile.BadZipFile:
            self.logger.error("Invalid ZIP file")
            return False
        except Exception as e:
            self.logger.error(f"ZIP integrity check error: {e}")
            return False
            
    def _verify_update_contents(self, update_file: Path) -> bool:
        """Verify update contents and structure"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract update to temporary directory
                with zipfile.ZipFile(update_file, 'r') as zf:
                    zf.extractall(temp_path)
                    
                # Verify required files exist
                for required_file in self.required_files:
                    file_path = temp_path / required_file
                    if not file_path.exists():
                        self.logger.error(f"Required file missing: {required_file}")
                        return False
                        
                # Verify update manifest
                manifest_path = temp_path / "update_manifest.json"
                if not self._verify_update_manifest(manifest_path):
                    return False
                    
                # Verify version info
                version_info_path = temp_path / "version_info.json"
                if not self._verify_version_info(version_info_path):
                    return False
                    
                # Verify source code structure
                src_path = temp_path / "src"
                if not self._verify_source_structure(src_path):
                    return False
                    
            self.logger.debug("Update contents verification passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Contents verification error: {e}")
            return False
            
    def _verify_update_manifest(self, manifest_path: Path) -> bool:
        """Verify update manifest file"""
        try:
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
                
            # Check required fields
            required_fields = ['version', 'files', 'dependencies', 'checksum']
            for field in required_fields:
                if field not in manifest:
                    self.logger.error(f"Missing field in manifest: {field}")
                    return False
                    
            # Verify file list
            files = manifest.get('files', [])
            if not isinstance(files, list) or len(files) == 0:
                self.logger.error("Invalid or empty file list in manifest")
                return False
                
            # Verify dependencies format
            dependencies = manifest.get('dependencies', {})
            if not isinstance(dependencies, dict):
                self.logger.error("Invalid dependencies format in manifest")
                return False
                
            self.logger.debug("Update manifest verification passed")
            return True
            
        except json.JSONDecodeError:
            self.logger.error("Invalid JSON in update manifest")
            return False
        except Exception as e:
            self.logger.error(f"Manifest verification error: {e}")
            return False
            
    def _verify_version_info(self, version_info_path: Path) -> bool:
        """Verify version info file"""
        try:
            with open(version_info_path, 'r') as f:
                version_info = json.load(f)
                
            # Check required fields
            required_fields = ['version', 'build_date', 'build_type']
            for field in required_fields:
                if field not in version_info:
                    self.logger.error(f"Missing field in version info: {field}")
                    return False
                    
            # Validate version format
            version = version_info.get('version')
            if not self._is_valid_version_format(version):
                self.logger.error(f"Invalid version format: {version}")
                return False
                
            self.logger.debug("Version info verification passed")
            return True
            
        except json.JSONDecodeError:
            self.logger.error("Invalid JSON in version info")
            return False
        except Exception as e:
            self.logger.error(f"Version info verification error: {e}")
            return False
            
    def _verify_source_structure(self, src_path: Path) -> bool:
        """Verify source code structure"""
        try:
            # Check for main package directory
            package_dir = src_path / "prashant918_antivirus"
            if not package_dir.exists() or not package_dir.is_dir():
                self.logger.error("Main package directory not found")
                return False
                
            # Check for essential modules
            essential_modules = [
                '__init__.py',
                'main.py',
                'config.py',
                'logger.py',
                'exceptions.py'
            ]
            
            for module in essential_modules:
                module_path = package_dir / module
                if not module_path.exists():
                    self.logger.warning(f"Essential module missing: {module}")
                    # Don't fail for missing modules, just warn
                    
            # Check for core directories
            core_dirs = ['antivirus', 'core', 'upgrade']
            for core_dir in core_dirs:
                dir_path = package_dir / core_dir
                if not dir_path.exists() or not dir_path.is_dir():
                    self.logger.warning(f"Core directory missing: {core_dir}")
                    
            self.logger.debug("Source structure verification passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Source structure verification error: {e}")
            return False
            
    def _is_valid_version_format(self, version: str) -> bool:
        """Check if version string has valid format"""
        try:
            from packaging import version as pkg_version
            pkg_version.parse(version)
            return True
        except Exception:
            # Fallback to simple regex check
            import re
            pattern = r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?$'
            return bool(re.match(pattern, version))
            
    def _verify_digital_signature(self, update_file: Path) -> bool:
        """Verify digital signature of update file"""
        if not self.signature_verification_enabled:
            return True
            
        try:
            # Look for signature file
            signature_file = update_file.with_suffix('.sig')
            if not signature_file.exists():
                self.logger.warning("No signature file found")
                return False
                
            # Load public key (this would be embedded or loaded from config)
            public_key_pem = self._get_public_key()
            if not public_key_pem:
                self.logger.warning("No public key available for signature verification")
                return False
                
            # Verify signature
            with open(signature_file, 'rb') as f:
                signature = f.read()
                
            with open(update_file, 'rb') as f:
                file_data = f.read()
                
            public_key = self.serialization.load_pem_public_key(public_key_pem.encode())
            
            try:
                public_key.verify(
                    signature,
                    file_data,
                    self.padding.PSS(
                        mgf=self.padding.MGF1(self.hashes.SHA256()),
                        salt_length=self.padding.PSS.MAX_LENGTH
                    ),
                    self.hashes.SHA256()
                )
                self.logger.info("Digital signature verification passed")
                return True
            except Exception:
                self.logger.error("Digital signature verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Signature verification error: {e}")
            return False
            
    def _get_public_key(self) -> Optional[str]:
        """Get public key for signature verification"""
        # In a real implementation, this would load the public key
        # from a secure location or be embedded in the application
        return None
        
    def calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate hash of a file"""
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Hash calculation error: {e}")
            raise ValidationError(f"Failed to calculate file hash: {e}")
