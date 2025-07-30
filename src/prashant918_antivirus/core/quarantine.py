"""
Prashant918 Advanced Antivirus - Enhanced Quarantine Manager
Advanced quarantine system with encryption, integrity verification, and secure file management
"""

import os
import shutil
import hashlib
import json
import time
import threading
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# Encryption imports with error handling
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    Fernet = None

# Core imports with error handling
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
    from ..exceptions import QuarantineError, QuarantineAccessError, ValidationError
except ImportError:
    class QuarantineError(Exception): pass
    class QuarantineAccessError(QuarantineError): pass
    class ValidationError(Exception): pass

try:
    from ..utils import calculate_file_hash, sanitize_filename, create_secure_temp_file
except ImportError:
    def calculate_file_hash(file_path, algorithm='sha256'):
        """Fallback hash calculation"""
        hash_obj = hashlib.new(algorithm)
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return None
    
    def sanitize_filename(filename):
        """Fallback filename sanitization"""
        import re
        return re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    def create_secure_temp_file():
        """Fallback temp file creation"""
        import tempfile
        return tempfile.NamedTemporaryFile(delete=False)

class QuarantineStatus(Enum):
    """Quarantine item status"""
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    DELETED = "deleted"
    CORRUPTED = "corrupted"

@dataclass
class QuarantineItem:
    """Quarantine item data structure"""
    id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    file_size: int
    threat_name: str
    detection_method: str
    quarantine_time: datetime
    status: QuarantineStatus = QuarantineStatus.QUARANTINED
    metadata: Dict[str, Any] = field(default_factory=dict)
    restore_count: int = 0
    last_accessed: Optional[datetime] = None

class QuarantineEncryption:
    """Enhanced quarantine file encryption with fallback support"""
    
    def __init__(self, password: Optional[str] = None):
        self.logger = SecureLogger("QuarantineEncryption")
        self.cipher_suite = None
        self.encryption_enabled = HAS_CRYPTOGRAPHY
        
        if self.encryption_enabled:
            self._initialize_encryption(password)
        else:
            self.logger.warning("Cryptography library not available - files will not be encrypted")
    
    def _initialize_encryption(self, password: Optional[str] = None):
        """Initialize encryption with password"""
        try:
            if not password:
                password = "default_quarantine_key_2024"
            
            # Generate key from password
            password_bytes = password.encode()
            salt = b'quarantine_salt_2024'  # In production, use random salt
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            self.cipher_suite = Fernet(key)
            
            self.logger.info("Quarantine encryption initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            self.encryption_enabled = False
    
    def encrypt_file(self, source_path: str, destination_path: str) -> bool:
        """Encrypt file to quarantine"""
        try:
            if not self.encryption_enabled:
                # Fallback: just copy the file
                shutil.copy2(source_path, destination_path)
                return True
            
            with open(source_path, 'rb') as src_file:
                file_data = src_file.read()
            
            encrypted_data = self.cipher_suite.encrypt(file_data)
            
            with open(destination_path, 'wb') as dst_file:
                dst_file.write(encrypted_data)
            
            # Set restrictive permissions
            if hasattr(os, 'chmod'):
                os.chmod(destination_path, 0o600)
            
            return True
            
        except Exception as e:
            self.logger.error(f"File encryption failed: {e}")
            return False
    
    def decrypt_file(self, source_path: str, destination_path: str) -> bool:
        """Decrypt file from quarantine"""
        try:
            if not self.encryption_enabled:
                # Fallback: just copy the file
                shutil.copy2(source_path, destination_path)
                return True
            
            with open(source_path, 'rb') as src_file:
                encrypted_data = src_file.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            with open(destination_path, 'wb') as dst_file:
                dst_file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"File decryption failed: {e}")
            return False
    
    def is_encryption_enabled(self) -> bool:
        """Check if encryption is enabled"""
        return self.encryption_enabled

class QuarantineManager:
    """Enhanced quarantine manager with comprehensive file management"""
    
    def __init__(self, quarantine_dir: Optional[str] = None):
        self.logger = SecureLogger("QuarantineManager")
        
        # Set up quarantine directory
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            home_dir = Path.home()
            self.quarantine_dir = home_dir / ".prashant918_antivirus" / "quarantine"
        
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up database
        self.db_path = self.quarantine_dir / "quarantine.db"
        self.db_lock = threading.Lock()
        
        # Initialize encryption
        self.encryption = QuarantineEncryption()
        
        # Configuration
        self.max_quarantine_size = secure_config.get("quarantine.max_size", 1024 * 1024 * 1024)  # 1GB
        self.retention_days = secure_config.get("quarantine.retention_days", 30)
        self.auto_cleanup_enabled = secure_config.get("quarantine.auto_cleanup", True)
        
        # Statistics
        self.stats = {
            'total_quarantined': 0,
            'total_restored': 0,
            'total_deleted': 0,
            'current_size': 0,
            'last_cleanup': None
        }
        
        # Initialize database and load stats
        self._initialize_database()
        self._load_statistics()
        
        # Set secure permissions
        self._set_secure_permissions()
    
    def _set_secure_permissions(self):
        """Set secure permissions on quarantine directory"""
        try:
            if hasattr(os, 'chmod') and os.name != 'nt':
                os.chmod(self.quarantine_dir, 0o700)
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Could not set secure permissions: {e}")
    
    def _initialize_database(self):
        """Initialize quarantine database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Create quarantine items table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine_items (
                        id TEXT PRIMARY KEY,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        threat_name TEXT NOT NULL,
                        detection_method TEXT NOT NULL,
                        quarantine_time TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'quarantined',
                        metadata TEXT DEFAULT '{}',
                        restore_count INTEGER DEFAULT 0,
                        last_accessed TEXT
                    )
                ''')
                
                # Create statistics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine_stats (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_quarantine_time 
                    ON quarantine_items(quarantine_time)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_status 
                    ON quarantine_items(status)
                ''')
                
                conn.commit()
                conn.close()
                
                self.logger.info("Quarantine database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise QuarantineError(f"Failed to initialize quarantine database: {e}")
    
    def quarantine_file(self, file_path: str, threat_name: str, detection_method: str, 
                       metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Quarantine a file"""
        try:
            file_path = Path(file_path).resolve()
            
            if not file_path.exists():
                raise ValidationError(f"File not found: {file_path}")
            
            # Calculate file hash and size
            file_hash = calculate_file_hash(str(file_path))
            if not file_hash:
                raise QuarantineError("Failed to calculate file hash")
            
            file_size = file_path.stat().st_size
            
            # Check quarantine size limits
            if not self._check_space_available(file_size):
                self._cleanup_old_items()
                if not self._check_space_available(file_size):
                    raise QuarantineError("Quarantine storage limit exceeded")
            
            # Generate unique quarantine ID
            quarantine_id = self._generate_quarantine_id(file_hash)
            
            # Create quarantine file path
            quarantine_filename = f"{quarantine_id}_{sanitize_filename(file_path.name)}.qtn"
            quarantine_path = self.quarantine_dir / quarantine_filename
            
            # Encrypt and move file to quarantine
            if not self.encryption.encrypt_file(str(file_path), str(quarantine_path)):
                raise QuarantineError("Failed to encrypt file for quarantine")
            
            # Create quarantine item
            quarantine_item = QuarantineItem(
                id=quarantine_id,
                original_path=str(file_path),
                quarantine_path=str(quarantine_path),
                file_hash=file_hash,
                file_size=file_size,
                threat_name=threat_name,
                detection_method=detection_method,
                quarantine_time=datetime.now(),
                metadata=metadata or {}
            )
            
            # Store in database
            self._store_quarantine_item(quarantine_item)
            
            # Remove original file
            try:
                file_path.unlink()
                self.logger.info(f"File quarantined successfully: {file_path}")
            except Exception as e:
                self.logger.warning(f"Failed to remove original file: {e}")
            
            # Update statistics
            self._update_statistics('quarantined', file_size)
            
            return quarantine_id
            
        except Exception as e:
            self.logger.error(f"Quarantine operation failed: {e}")
            raise QuarantineError(f"Failed to quarantine file: {e}")
    
    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore a quarantined file"""
        try:
            # Get quarantine item
            item = self._get_quarantine_item(quarantine_id)
            if not item:
                raise ValidationError(f"Quarantine item not found: {quarantine_id}")
            
            if item.status != QuarantineStatus.QUARANTINED:
                raise ValidationError(f"Item is not in quarantined status: {item.status}")
            
            # Determine restore path
            if restore_path:
                restore_path = Path(restore_path)
            else:
                restore_path = Path(item.original_path)
            
            # Ensure restore directory exists
            restore_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Decrypt and restore file
            quarantine_path = Path(item.quarantine_path)
            if not quarantine_path.exists():
                raise QuarantineError(f"Quarantined file not found: {quarantine_path}")
            
            if not self.encryption.decrypt_file(str(quarantine_path), str(restore_path)):
                raise QuarantineError("Failed to decrypt quarantined file")
            
            # Verify file integrity
            restored_hash = calculate_file_hash(str(restore_path))
            if restored_hash != item.file_hash:
                restore_path.unlink()  # Remove corrupted file
                raise QuarantineError("File integrity check failed after restoration")
            
            # Update item status
            item.status = QuarantineStatus.RESTORED
            item.restore_count += 1
            item.last_accessed = datetime.now()
            self._update_quarantine_item(item)
            
            # Remove quarantined file
            try:
                quarantine_path.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to remove quarantined file: {e}")
            
            # Update statistics
            self._update_statistics('restored', -item.file_size)
            
            self.logger.info(f"File restored successfully: {restore_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Restore operation failed: {e}")
            raise QuarantineError(f"Failed to restore file: {e}")
    
    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file"""
        try:
            # Get quarantine item
            item = self._get_quarantine_item(quarantine_id)
            if not item:
                raise ValidationError(f"Quarantine item not found: {quarantine_id}")
            
            # Remove quarantined file
            quarantine_path = Path(item.quarantine_path)
            if quarantine_path.exists():
                # Secure deletion (overwrite with random data)
                self._secure_delete_file(quarantine_path)
            
            # Update item status
            item.status = QuarantineStatus.DELETED
            item.last_accessed = datetime.now()
            self._update_quarantine_item(item)
            
            # Update statistics
            self._update_statistics('deleted', -item.file_size)
            
            self.logger.info(f"Quarantined file deleted permanently: {quarantine_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Delete operation failed: {e}")
            raise QuarantineError(f"Failed to delete quarantined file: {e}")
    
    def list_quarantined_files(self, status: Optional[QuarantineStatus] = None, 
                              limit: int = 100) -> List[QuarantineItem]:
        """List quarantined files"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if status:
                    cursor.execute('''
                        SELECT * FROM quarantine_items 
                        WHERE status = ? 
                        ORDER BY quarantine_time DESC 
                        LIMIT ?
                    ''', (status.value, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM quarantine_items 
                        ORDER BY quarantine_time DESC 
                        LIMIT ?
                    ''', (limit,))
                
                items = []
                for row in cursor.fetchall():
                    item = self._row_to_quarantine_item(row)
                    items.append(item)
                
                conn.close()
                return items
                
        except Exception as e:
            self.logger.error(f"Failed to list quarantined files: {e}")
            return []
    
    def get_quarantine_statistics(self) -> Dict[str, Any]:
        """Get quarantine statistics"""
        try:
            # Update current size
            current_size = self._calculate_current_size()
            self.stats['current_size'] = current_size
            
            # Get item counts by status
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT status, COUNT(*) FROM quarantine_items 
                    GROUP BY status
                ''')
                
                status_counts = {}
                for status, count in cursor.fetchall():
                    status_counts[status] = count
                
                conn.close()
            
            return {
                **self.stats,
                'status_counts': status_counts,
                'quarantine_dir': str(self.quarantine_dir),
                'encryption_enabled': self.encryption.is_encryption_enabled(),
                'max_size': self.max_quarantine_size,
                'retention_days': self.retention_days
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return self.stats
    
    def cleanup_old_items(self, days: Optional[int] = None) -> int:
        """Clean up old quarantined items"""
        try:
            if days is None:
                days = self.retention_days
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get old items
                cursor.execute('''
                    SELECT * FROM quarantine_items 
                    WHERE quarantine_time < ? AND status = 'quarantined'
                ''', (cutoff_date.isoformat(),))
                
                old_items = cursor.fetchall()
                cleaned_count = 0
                
                for row in old_items:
                    item = self._row_to_quarantine_item(row)
                    
                    # Remove file
                    quarantine_path = Path(item.quarantine_path)
                    if quarantine_path.exists():
                        self._secure_delete_file(quarantine_path)
                    
                    # Update status
                    cursor.execute('''
                        UPDATE quarantine_items 
                        SET status = 'deleted', last_accessed = ? 
                        WHERE id = ?
                    ''', (datetime.now().isoformat(), item.id))
                    
                    cleaned_count += 1
                
                conn.commit()
                conn.close()
                
                # Update statistics
                self.stats['last_cleanup'] = datetime.now().isoformat()
                self._save_statistics()
                
                self.logger.info(f"Cleaned up {cleaned_count} old quarantine items")
                return cleaned_count
                
        except Exception as e:
            self.logger.error(f"Cleanup operation failed: {e}")
            return 0
    
    def _generate_quarantine_id(self, file_hash: str) -> str:
        """Generate unique quarantine ID"""
        timestamp = str(int(time.time()))
        unique_data = f"{file_hash}_{timestamp}"
        return hashlib.sha256(unique_data.encode()).hexdigest()[:16]
    
    def _check_space_available(self, file_size: int) -> bool:
        """Check if space is available for quarantine"""
        current_size = self._calculate_current_size()
        return (current_size + file_size) <= self.max_quarantine_size
    
    def _calculate_current_size(self) -> int:
        """Calculate current quarantine directory size"""
        try:
            total_size = 0
            for file_path in self.quarantine_dir.rglob("*.qtn"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            return total_size
        except Exception:
            return 0
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete a file by overwriting with random data"""
        try:
            if not file_path.exists():
                return
            
            file_size = file_path.stat().st_size
            
            # Overwrite with random data (3 passes)
            with open(file_path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove file
            file_path.unlink()
            
        except Exception as e:
            self.logger.warning(f"Secure deletion failed, using normal deletion: {e}")
            try:
                file_path.unlink()
            except Exception:
                pass
    
    def _store_quarantine_item(self, item: QuarantineItem):
        """Store quarantine item in database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO quarantine_items 
                    (id, original_path, quarantine_path, file_hash, file_size, 
                     threat_name, detection_method, quarantine_time, status, 
                     metadata, restore_count, last_accessed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    item.id, item.original_path, item.quarantine_path,
                    item.file_hash, item.file_size, item.threat_name,
                    item.detection_method, item.quarantine_time.isoformat(),
                    item.status.value, json.dumps(item.metadata),
                    item.restore_count,
                    item.last_accessed.isoformat() if item.last_accessed else None
                ))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Failed to store quarantine item: {e}")
            raise QuarantineError(f"Database storage failed: {e}")
    
    def _get_quarantine_item(self, quarantine_id: str) -> Optional[QuarantineItem]:
        """Get quarantine item from database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM quarantine_items WHERE id = ?
                ''', (quarantine_id,))
                
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    return self._row_to_quarantine_item(row)
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get quarantine item: {e}")
            return None
    
    def _update_quarantine_item(self, item: QuarantineItem):
        """Update quarantine item in database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE quarantine_items 
                    SET status = ?, metadata = ?, restore_count = ?, last_accessed = ?
                    WHERE id = ?
                ''', (
                    item.status.value, json.dumps(item.metadata),
                    item.restore_count,
                    item.last_accessed.isoformat() if item.last_accessed else None,
                    item.id
                ))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Failed to update quarantine item: {e}")
            raise QuarantineError(f"Database update failed: {e}")
    
    def _row_to_quarantine_item(self, row) -> QuarantineItem:
        """Convert database row to QuarantineItem"""
        return QuarantineItem(
            id=row[0],
            original_path=row[1],
            quarantine_path=row[2],
            file_hash=row[3],
            file_size=row[4],
            threat_name=row[5],
            detection_method=row[6],
            quarantine_time=datetime.fromisoformat(row[7]),
            status=QuarantineStatus(row[8]),
            metadata=json.loads(row[9]) if row[9] else {},
            restore_count=row[10],
            last_accessed=datetime.fromisoformat(row[11]) if row[11] else None
        )
    
    def _cleanup_old_items(self):
        """Internal cleanup method"""
        if self.auto_cleanup_enabled:
            self.cleanup_old_items()
    
    def _update_statistics(self, operation: str, size_change: int = 0):
        """Update statistics"""
        if operation == 'quarantined':
            self.stats['total_quarantined'] += 1
        elif operation == 'restored':
            self.stats['total_restored'] += 1
        elif operation == 'deleted':
            self.stats['total_deleted'] += 1
        
        self.stats['current_size'] += size_change
        self._save_statistics()
    
    def _load_statistics(self):
        """Load statistics from database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT key, value FROM quarantine_stats')
                for key, value in cursor.fetchall():
                    if key in self.stats:
                        try:
                            self.stats[key] = int(value) if value.isdigit() else value
                        except (ValueError, AttributeError):
                            self.stats[key] = value
                
                conn.close()
                
        except Exception as e:
            self.logger.debug(f"Failed to load statistics: {e}")
    
    def _save_statistics(self):
        """Save statistics to database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for key, value in self.stats.items():
                    cursor.execute('''
                        INSERT OR REPLACE INTO quarantine_stats 
                        (key, value, updated_at) VALUES (?, ?, ?)
                    ''', (key, str(value), datetime.now().isoformat()))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.debug(f"Failed to save statistics: {e}")
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify integrity of quarantined files"""
        try:
            items = self.list_quarantined_files(QuarantineStatus.QUARANTINED)
            
            results = {
                'total_checked': 0,
                'corrupted_files': [],
                'missing_files': [],
                'intact_files': 0
            }
            
            for item in items:
                results['total_checked'] += 1
                quarantine_path = Path(item.quarantine_path)
                
                if not quarantine_path.exists():
                    results['missing_files'].append(item.id)
                    continue
                
                # For encrypted files, we can't easily verify without decrypting
                # So we just check if the file exists and has reasonable size
                if quarantine_path.stat().st_size == 0:
                    results['corrupted_files'].append(item.id)
                else:
                    results['intact_files'] += 1
            
            return results
            
        except Exception as e:
            self.logger.error(f"Integrity verification failed: {e}")
            return {'error': str(e)}
    
    def export_quarantine_info(self, export_path: str) -> bool:
        """Export quarantine information to file"""
        try:
            items = self.list_quarantined_files()
            stats = self.get_quarantine_statistics()
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'statistics': stats,
                'items': []
            }
            
            for item in items:
                export_data['items'].append({
                    'id': item.id,
                    'original_path': item.original_path,
                    'file_hash': item.file_hash,
                    'file_size': item.file_size,
                    'threat_name': item.threat_name,
                    'detection_method': item.detection_method,
                    'quarantine_time': item.quarantine_time.isoformat(),
                    'status': item.status.value,
                    'restore_count': item.restore_count
                })
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Quarantine information exported to: {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False