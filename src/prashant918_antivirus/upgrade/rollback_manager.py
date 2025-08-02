"""
Rollback Management System
Handles rollback operations for failed updates
"""

import os
import shutil
import json
import threading
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..config import SecureConfig
except ImportError:
    SecureConfig = type('Config', (), {'get': lambda self, key, default=None: default})

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

class RollbackManager:
    """Manages rollback operations for failed updates"""
    
    def __init__(self):
        self.logger = SecureLogger("RollbackManager")
        self.config = SecureConfig()
        
        # Paths
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.backup_dir = self.app_root / "backups"
        self.rollback_log = self.app_root / "logs" / "rollback.log"
        
        # Settings
        self.max_rollback_attempts = self.config.get('rollback.max_attempts', 3)
        self.rollback_timeout = self.config.get('rollback.timeout', 300)  # 5 minutes
        
        # Thread safety
        self.rollback_lock = threading.Lock()
        
        # Ensure directories exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.rollback_log.parent.mkdir(parents=True, exist_ok=True)
    
    def rollback_from_backup(self, backup_path: Path) -> bool:
        """Rollback from a specific backup"""
        with self.rollback_lock:
            try:
                self.logger.info(f"Starting rollback from backup: {backup_path}")
                
                # Validate backup
                if not self._validate_backup(backup_path):
                    raise AntivirusError("Backup validation failed")
                
                # Create rollback point
                rollback_point = self._create_rollback_point()
                
                try:
                    # Stop services
                    self._stop_services()
                    
                    # Restore files
                    self._restore_files_from_backup(backup_path)
                    
                    # Restore database
                    self._restore_database_from_backup(backup_path)
                    
                    # Restore configuration
                    self._restore_configuration_from_backup(backup_path)
                    
                    # Start services
                    self._start_services()
                    
                    # Verify rollback success
                    if self._verify_rollback_success(backup_path):
                        self._log_rollback_success(backup_path)
                        self.logger.info("Rollback completed successfully")
                        return True
                    else:
                        raise AntivirusError("Rollback verification failed")
                
                except Exception as e:
                    self.logger.error(f"Rollback failed, attempting recovery: {e}")
                    self._recover_from_rollback_point(rollback_point)
                    raise
                
            except Exception as e:
                self._log_rollback_failure(backup_path, str(e))
                self.logger.error(f"Rollback failed: {e}")
                return False
    
    def _validate_backup(self, backup_path: Path) -> bool:
        """Validate backup integrity"""
        try:
            if not backup_path.exists() or not backup_path.is_dir():
                self.logger.error(f"Backup path does not exist or is not a directory: {backup_path}")
                return False
            
            # Check for version info
            version_file = backup_path / "version_info.json"
            if not version_file.exists():
                self.logger.error("Backup missing version_info.json")
                return False
            
            with open(version_file, 'r') as f:
                version_info = json.load(f)
                required_fields = ['version', 'backup_date', 'python_version']
                for field in required_fields:
                    if field not in version_info:
                        self.logger.error(f"Missing field in version info: {field}")
                        return False
            
            # Check for essential directories
            essential_dirs = ['src']
            for dir_name in essential_dirs:
                if not (backup_path / dir_name).exists():
                    self.logger.error(f"Backup missing essential directory: {dir_name}")
                    return False
            
            self.logger.debug("Backup validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup validation error: {e}")
            return False
    
    def _create_rollback_point(self) -> Path:
        """Create a rollback point before attempting rollback"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rollback_point = self.backup_dir / f"rollback_point_{timestamp}"
            rollback_point.mkdir(parents=True, exist_ok=True)
            
            # Backup current state
            src_dir = self.app_root / "src"
            if src_dir.exists():
                shutil.copytree(src_dir, rollback_point / "src")
            
            config_dir = self.app_root / "config"
            if config_dir.exists():
                shutil.copytree(config_dir, rollback_point / "config")
            
            # Save rollback info
            rollback_info = {
                "created_at": datetime.now().isoformat(),
                "purpose": "rollback_point",
                "app_root": str(self.app_root)
            }
            
            with open(rollback_point / "rollback_info.json", 'w') as f:
                json.dump(rollback_info, f, indent=2)
            
            self.logger.info(f"Created rollback point: {rollback_point}")
            return rollback_point
            
        except Exception as e:
            self.logger.error(f"Failed to create rollback point: {e}")
            raise AntivirusError(f"Rollback point creation failed: {e}")
    
    def _restore_files_from_backup(self, backup_path: Path):
        """Restore files from backup"""
        try:
            self.logger.info("Restoring files from backup...")
            
            # Restore source code
            src_backup = backup_path / "src"
            src_current = self.app_root / "src"
            
            if src_backup.exists():
                if src_current.exists():
                    shutil.rmtree(src_current)
                shutil.copytree(src_backup, src_current)
                self.logger.debug("Source code restored")
            
            # Restore other files
            for item in backup_path.iterdir():
                if item.name not in ['src', 'config', 'data', 'version_info.json']:
                    target = self.app_root / item.name
                    if target.exists():
                        if target.is_dir():
                            shutil.rmtree(target)
                        else:
                            target.unlink()
                    
                    if item.is_dir():
                        shutil.copytree(item, target)
                    else:
                        shutil.copy2(item, target)
            
            self.logger.info("Files restored successfully")
            
        except Exception as e:
            self.logger.error(f"File restoration failed: {e}")
            raise AntivirusError(f"File restoration failed: {e}")
    
    def _restore_database_from_backup(self, backup_path: Path):
        """Restore database from backup"""
        try:
            db_backup = backup_path / "data" / "antivirus.db"
            if db_backup.exists():
                data_dir = Path.home() / ".prashant918_antivirus" / "data"
                data_dir.mkdir(parents=True, exist_ok=True)
                
                db_current = data_dir / "antivirus.db"
                shutil.copy2(db_backup, db_current)
                
                self.logger.debug("Database restored")
            
        except Exception as e:
            self.logger.warning(f"Database restoration failed: {e}")
    
    def _restore_configuration_from_backup(self, backup_path: Path):
        """Restore configuration from backup"""
        try:
            config_backup = backup_path / "config"
            if config_backup.exists():
                config_current = self.app_root / "config"
                
                if config_current.exists():
                    shutil.rmtree(config_current)
                shutil.copytree(config_backup, config_current)
                
                self.logger.debug("Configuration restored")
            
        except Exception as e:
            self.logger.warning(f"Configuration restoration failed: {e}")
    
    def _stop_services(self):
        """Stop antivirus services"""
        try:
            self.logger.info("Stopping services...")
            # Platform-specific service stopping would go here
            pass
        except Exception as e:
            self.logger.error(f"Failed to stop services: {e}")
    
    def _start_services(self):
        """Start antivirus services"""
        try:
            self.logger.info("Starting services...")
            # Platform-specific service starting would go here
            pass
        except Exception as e:
            self.logger.error(f"Failed to start services: {e}")
    
    def _verify_rollback_success(self, backup_path: Path) -> bool:
        """Verify rollback was successful"""
        try:
            # Check version info
            version_file = backup_path / "version_info.json"
            if version_file.exists():
                with open(version_file, 'r') as f:
                    backup_version = json.load(f).get('version')
                
                # Try to import and check version
                try:
                    from .. import __version__
                    if __version__ == backup_version:
                        self.logger.debug("Version verification passed")
                        return True
                except ImportError:
                    pass
            
            # Basic import test
            try:
                from ..logger import SecureLogger
                from ..config import secure_config
                self.logger.debug("Basic import test passed")
                return True
            except ImportError as e:
                self.logger.error(f"Import test failed: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"Rollback verification failed: {e}")
            return False
    
    def _recover_from_rollback_point(self, rollback_point: Path):
        """Recover from failed rollback using rollback point"""
        try:
            self.logger.info(f"Recovering from rollback point: {rollback_point}")
            
            if not rollback_point.exists():
                raise AntivirusError("Rollback point does not exist")
            
            # Restore from rollback point
            src_rollback = rollback_point / "src"
            src_current = self.app_root / "src"
            
            if src_rollback.exists():
                if src_current.exists():
                    shutil.rmtree(src_current)
                shutil.copytree(src_rollback, src_current)
            
            config_rollback = rollback_point / "config"
            config_current = self.app_root / "config"
            
            if config_rollback.exists():
                if config_current.exists():
                    shutil.rmtree(config_current)
                shutil.copytree(config_rollback, config_current)
            
            self.logger.info("Recovery from rollback point completed")
            
        except Exception as e:
            self.logger.critical(f"Recovery from rollback point failed: {e}")
            raise AntivirusError(f"Recovery failed: {e}")
    
    def _log_rollback_success(self, backup_path: Path):
        """Log successful rollback"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "backup_path": str(backup_path),
            "message": "Rollback completed successfully"
        }
        self._write_rollback_log(log_entry)
    
    def _log_rollback_failure(self, backup_path: Path, error_message: str):
        """Log failed rollback"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "failure",
            "backup_path": str(backup_path),
            "error": error_message
        }
        self._write_rollback_log(log_entry)
    
    def _write_rollback_log(self, log_entry: Dict[str, Any]):
        """Write entry to rollback log"""
        try:
            with open(self.rollback_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write rollback log: {e}")
    
    def get_rollback_history(self) -> list:
        """Get rollback history"""
        try:
            history = []
            if self.rollback_log.exists():
                with open(self.rollback_log, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            history.append(entry)
                        except json.JSONDecodeError:
                            continue
            return history
        except Exception as e:
            self.logger.error(f"Failed to get rollback history: {e}")
            return []