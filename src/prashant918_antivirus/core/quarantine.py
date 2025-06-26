"""
Prashant918 Advanced Antivirus - Quarantine Manager

Advanced quarantine system with encryption, integrity verification,
and secure file management capabilities.
"""

import os
import shutil
import hashlib
import json
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from ..logger import SecureLogger
from ..config import secure_config
from ..database import db_manager
from ..exceptions import QuarantineError, QuarantineAccessError, ValidationError
from ..utils import calculate_file_hash, sanitize_filename, create_secure_temp_file


class QuarantineEncryption:
    """Handle encryption/decryption for quarantined files"""
    
    def __init__(self):
        self.logger = SecureLogger("QuarantineEncryption")
        self.key_file = "config/.quarantine_key"
        self.cipher_suite = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption system"""
        try:
            if not os.path.exists(self.key_file):
                self._generate_key()
            
            with open(self.key_file, 'rb') as f:
                key = f.read()
            
            self.cipher_suite = Fernet(key)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize quarantine encryption: {e}")
            raise QuarantineError(f"Encryption initialization failed: {e}")
    
    def _generate_key(self):
        """Generate new encryption key"""
        try:
            # Generate random password
            password = os.urandom(32)
            salt = os.urandom(16)
            
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Ensure config directory exists
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            
            # Save key with secure permissions
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            os.chmod(self.key_file, 0o600)
            
        except Exception as e:
            self.logger.error(f"Failed to generate quarantine key: {e}")
            raise QuarantineError(f"Key generation failed: {e}")
    
    def encrypt_file(self, source_path: str, dest_path: str) -> bool:
        """Encrypt file for quarantine"""
        try:
            with open(source_path, 'rb') as src_file:
                file_data = src_file.read()
            
            encrypted_data = self.cipher_suite.encrypt(file_data)
            
            with open(dest_path, 'wb') as dest_file:
                dest_file.write(encrypted_data)
            
            # Set secure permissions
            os.chmod(dest_path, 0o600)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to encrypt file {source_path}: {e}")
            return False
    
    def decrypt_file(self, source_path: str, dest_path: str) -> bool:
        """Decrypt file from quarantine"""
        try:
            with open(source_path, 'rb') as src_file:
                encrypted_data = src_file.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            with open(dest_path, 'wb') as dest_file:
                dest_file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt file {source_path}: {e}")
            return False


class QuarantineManager:
    """Advanced quarantine management system"""
    
    def __init__(self):
        self.logger = SecureLogger("QuarantineManager")
        self.quarantine_dir = "quarantine"
        self.metadata_dir = os.path.join(self.quarantine_dir, ".metadata")
        self.encryption = QuarantineEncryption()
        self.lock = threading.Lock()
        
        # Configuration
        self.max_quarantine_size = secure_config.get("quarantine.max_size", 1024 * 1024 * 1024)  # 1GB
        self.retention_days = secure_config.get("quarantine.retention_days", 30)
        self.auto_cleanup = secure_config.get("quarantine.auto_cleanup", True)
        
        self._initialize_quarantine_dir()
        
        if self.auto_cleanup:
            self._start_cleanup_thread()
    
    def _initialize_quarantine_dir(self):
        """Initialize quarantine directory structure"""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            os.makedirs(self.metadata_dir, exist_ok=True)
            
            # Set secure permissions
            os.chmod(self.quarantine_dir, 0o700)
            os.chmod(self.metadata_dir, 0o700)
            
            self.logger.info("Quarantine directory initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize quarantine directory: {e}")
            raise QuarantineError(f"Quarantine initialization failed: {e}")
    
    def quarantine_file(self, file_path: str, reason: str = "", 
                       threat_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Quarantine a file with encryption and metadata"""
        try:
            with self.lock:
                if not os.path.exists(file_path):
                    raise ValidationError(f"File not found: {file_path}")
                
                if not os.path.isfile(file_path):
                    raise ValidationError(f"Path is not a file: {file_path}")
                
                # Generate quarantine filename
                file_hash = calculate_file_hash(file_path)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                original_name = sanitize_filename(os.path.basename(file_path))
                quarantine_name = f"{timestamp}_{file_hash[:8]}_{original_name}.quar"
                quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
                
                # Create metadata
                metadata = self._create_metadata(file_path, reason, threat_info)
                
                # Encrypt and move file to quarantine
                if secure_config.get("quarantine.encryption", True):
                    success = self.encryption.encrypt_file(file_path, quarantine_path)
                else:
                    shutil.copy2(file_path, quarantine_path)
                    os.chmod(quarantine_path, 0o600)
                    success = True
                
                if not success:
                    raise QuarantineError("Failed to encrypt file for quarantine")
                
                # Save metadata
                metadata_path = os.path.join(self.metadata_dir, f"{quarantine_name}.json")
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                os.chmod(metadata_path, 0o600)
                
                # Store in database
                self._store_quarantine_record(metadata, quarantine_path)
                
                # Securely delete original file
                if secure_config.get("quarantine.secure_delete", True):
                    self._secure_delete(file_path)
                else:
                    os.remove(file_path)
                
                self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
                
                return {
                    'success': True,
                    'quarantine_path': quarantine_path,
                    'quarantine_id': metadata['quarantine_id'],
                    'metadata': metadata
                }
                
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> Dict[str, Any]:
        """Restore file from quarantine"""
        try:
            with self.lock:
                # Get quarantine record
                record = self._get_quarantine_record(quarantine_id)
                if not record:
                    raise QuarantineError(f"Quarantine record not found: {quarantine_id}")
                
                quarantine_path = record['quarantine_path']
                original_path = record['original_path']
                
                if not os.path.exists(quarantine_path):
                    raise QuarantineError(f"Quarantined file not found: {quarantine_path}")
                
                # Determine restore path
                if restore_path is None:
                    restore_path = original_path
                
                # Ensure restore directory exists
                os.makedirs(os.path.dirname(restore_path), exist_ok=True)
                
                # Decrypt and restore file
                if record.get('encrypted', True):
                    success = self.encryption.decrypt_file(quarantine_path, restore_path)
                else:
                    shutil.copy2(quarantine_path, restore_path)
                    success = True
                
                if not success:
                    raise QuarantineError("Failed to decrypt file from quarantine")
                
                # Restore original permissions if available
                if 'original_permissions' in record:
                    try:
                        os.chmod(restore_path, int(record['original_permissions'], 8))
                    except:
                        pass
                
                # Update database record
                self._update_quarantine_status(quarantine_id, 'RESTORED', restore_path)
                
                self.logger.info(f"File restored: {quarantine_path} -> {restore_path}")
                
                return {
                    'success': True,
                    'restore_path': restore_path,
                    'original_path': original_path
                }
                
        except Exception as e:
            self.logger.error(f"Failed to restore file {quarantine_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_quarantined_file(self, quarantine_id: str) -> Dict[str, Any]:
        """Permanently delete quarantined file"""
        try:
            with self.lock:
                # Get quarantine record
                record = self._get_quarantine_record(quarantine_id)
                if not record:
                    raise QuarantineError(f"Quarantine record not found: {quarantine_id}")
                
                quarantine_path = record['quarantine_path']
                
                # Securely delete quarantined file
                if os.path.exists(quarantine_path):
                    self._secure_delete(quarantine_path)
                
                # Delete metadata file
                metadata_path = quarantine_path.replace(self.quarantine_dir, self.metadata_dir) + ".json"
                if os.path.exists(metadata_path):
                    self._secure_delete(metadata_path)
                
                # Update database record
                self._update_quarantine_status(quarantine_id, 'DELETED')
                
                self.logger.info(f"Quarantined file permanently deleted: {quarantine_id}")
                
                return {
                    'success': True,
                    'quarantine_id': quarantine_id
                }
                
        except Exception as e:
            self.logger.error(f"Failed to delete quarantined file {quarantine_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_quarantined_items(self, status: str = 'QUARANTINED') -> List[Dict[str, Any]]:
        """List quarantined items"""
        try:
            query = """
                SELECT quarantine_id, original_path, quarantine_path, file_hash,
                       threat_name, quarantine_reason, quarantined_at, status
                FROM quarantine_items
                WHERE status = :status
                ORDER BY quarantined_at DESC
            """
            
            results = db_manager.execute_query(query, {'status': status})
            
            items = []
            for row in results:
                items.append({
                    'quarantine_id': row[0],
                    'original_path': row[1],
                    'quarantine_path': row[2],
                    'file_hash': row[3],
                    'threat_name': row[4],
                    'quarantine_reason': row[5],
                    'quarantined_at': row[6].isoformat() if row[6] else None,
                    'status': row[7]
                })
            
            return items
            
        except Exception as e:
            self.logger.error(f"Failed to list quarantined items: {e}")
            return []
    
    def get_quarantine_stats(self) -> Dict[str, Any]:
        """Get quarantine statistics"""
        try:
            stats_query = """
                SELECT status, COUNT(*) as count
                FROM quarantine_items
                GROUP BY status
            """
            
            results = db_manager.execute_query(stats_query)
            status_counts = {row[0]: row[1] for row in results}
            
            # Calculate disk usage
            total_size = 0
            if os.path.exists(self.quarantine_dir):
                for root, dirs, files in os.walk(self.quarantine_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            total_size += os.path.getsize(file_path)
                        except:
                            pass
            
            return {
                'status_counts': status_counts,
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'quarantine_dir': self.quarantine_dir,
                'max_size_mb': round(self.max_quarantine_size / (1024 * 1024), 2),
                'retention_days': self.retention_days
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine stats: {e}")
            return {}
    
    def cleanup_old_items(self, days: Optional[int] = None) -> int:
        """Clean up old quarantine items"""
        try:
            if days is None:
                days = self.retention_days
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Get old items
            query = """
                SELECT quarantine_id, quarantine_path
                FROM quarantine_items
                WHERE quarantined_at < :cutoff_date
                AND status IN ('QUARANTINED', 'RESTORED')
            """
            
            results = db_manager.execute_query(query, {'cutoff_date': cutoff_date})
            
            cleaned_count = 0
            for quarantine_id, quarantine_path in results:
                try:
                    # Delete files
                    if os.path.exists(quarantine_path):
                        self._secure_delete(quarantine_path)
                    
                    # Delete metadata
                    metadata_path = quarantine_path.replace(self.quarantine_dir, self.metadata_dir) + ".json"
                    if os.path.exists(metadata_path):
                        self._secure_delete(metadata_path)
                    
                    # Update database
                    self._update_quarantine_status(quarantine_id, 'CLEANED')
                    
                    cleaned_count += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to clean quarantine item {quarantine_id}: {e}")
            
            self.logger.info(f"Cleaned {cleaned_count} old quarantine items")
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old items: {e}")
            return 0
    
    def _create_metadata(self, file_path: str, reason: str, 
                        threat_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Create metadata for quarantined file"""
        try:
            file_stat = os.stat(file_path)
            
            metadata = {
                'quarantine_id': self._generate_quarantine_id(),
                'original_path': os.path.abspath(file_path),
                'original_name': os.path.basename(file_path),
                'file_size': file_stat.st_size,
                'file_hash': calculate_file_hash(file_path),
                'quarantine_reason': reason,
                'quarantined_at': datetime.now().isoformat(),
                'original_permissions': oct(file_stat.st_mode)[-3:],
                'original_mtime': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                'encrypted': secure_config.get("quarantine.encryption", True),
                'threat_info': threat_info or {},
                'system_info': {
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                    'user': os.getenv('USER') or os.getenv('USERNAME', 'unknown'),
                    'platform': os.name
                }
            }
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Failed to create metadata: {e}")
            raise QuarantineError(f"Metadata creation failed: {e}")
    
    def _generate_quarantine_id(self) -> str:
        """Generate unique quarantine ID"""
        timestamp = str(int(time.time() * 1000))
        random_part = os.urandom(4).hex()
        return f"QUAR_{timestamp}_{random_part}"
    
    def _store_quarantine_record(self, metadata: Dict[str, Any], quarantine_path: str):
        """Store quarantine record in database"""
        try:
            query = """
                INSERT INTO quarantine_items 
                (quarantine_id, original_path, quarantine_path, file_hash, 
                 threat_name, quarantine_reason, quarantined_at, status)
                VALUES (:quarantine_id, :original_path, :quarantine_path, :file_hash,
                        :threat_name, :quarantine_reason, :quarantined_at, :status)
            """
            
            threat_name = "Unknown"
            if metadata.get('threat_info') and metadata['threat_info'].get('detections'):
                threat_name = metadata['threat_info']['detections'][0].get('threat_name', 'Unknown')
            
            params = {
                'quarantine_id': metadata['quarantine_id'],
                'original_path': metadata['original_path'],
                'quarantine_path': quarantine_path,
                'file_hash': metadata['file_hash'],
                'threat_name': threat_name,
                'quarantine_reason': metadata['quarantine_reason'],
                'quarantined_at': datetime.fromisoformat(metadata['quarantined_at']),
                'status': 'QUARANTINED'
            }
            
            db_manager.execute_command(query, params)
            
        except Exception as e:
            self.logger.error(f"Failed to store quarantine record: {e}")
            raise QuarantineError(f"Database storage failed: {e}")
    
    def _get_quarantine_record(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Get quarantine record from database"""
        try:
            query = """
                SELECT quarantine_id, original_path, quarantine_path, file_hash,
                       threat_name, quarantine_reason, quarantined_at, status
                FROM quarantine_items
                WHERE quarantine_id = :quarantine_id
            """
            
            results = db_manager.execute_query(query, {'quarantine_id': quarantine_id})
            
            if results:
                row = results[0]
                return {
                    'quarantine_id': row[0],
                    'original_path': row[1],
                    'quarantine_path': row[2],
                    'file_hash': row[3],
                    'threat_name': row[4],
                    'quarantine_reason': row[5],
                    'quarantined_at': row[6],
                    'status': row[7],
                    'encrypted': True  # Assume encrypted by default
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine record: {e}")
            return None
    
    def _update_quarantine_status(self, quarantine_id: str, status: str, 
                                 restore_path: Optional[str] = None):
        """Update quarantine status in database"""
        try:
            if restore_path:
                query = """
                    UPDATE quarantine_items 
                    SET status = :status, restored_at = CURRENT_TIMESTAMP
                    WHERE quarantine_id = :quarantine_id
                """
            else:
                query = """
                    UPDATE quarantine_items 
                    SET status = :status
                    WHERE quarantine_id = :quarantine_id
                """
            
            params = {
                'quarantine_id': quarantine_id,
                'status': status
            }
            
            db_manager.execute_command(query, params)
            
        except Exception as e:
            self.logger.error(f"Failed to update quarantine status: {e}")
    
    def _secure_delete(self, file_path: str):
        """Securely delete file by overwriting with random data"""
        try:
            if not os.path.exists(file_path):
                return
            
            file_size = os.path.getsize(file_path)
            
            # Overwrite file with random data multiple times
            with open(file_path, 'r+b') as f:
                for _ in range(3):  # 3 passes
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            os.remove(file_path)
            
        except Exception as e:
            self.logger.error(f"Failed to securely delete {file_path}: {e}")
            # Fallback to regular delete
            try:
                os.remove(file_path)
            except:
                pass
    
    def _start_cleanup_thread(self):
        """Start automatic cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(3600)  # Run every hour
                    self.cleanup_old_items()
                except Exception as e:
                    self.logger.error(f"Cleanup thread error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        self.logger.info("Automatic cleanup thread started")
