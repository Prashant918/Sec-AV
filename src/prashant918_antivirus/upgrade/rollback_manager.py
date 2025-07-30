"""
Rollback Manager
Handles rollback operations when updates fail
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import AntivirusError


class RollbackManager:
    """
    Manages rollback operations for failed updates
    """
    
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
        
        # State
        self.rollback_in_progress = False
        self.rollback_lock = threading.Lock()
        
    def rollback_from_backup(self, backup_path: Path) -> bool:
        """Rollback from a specific backup"""
        with self.rollback_lock:
            if self.rollback_in_progress:
                self.logger.warning("Rollback already in progress")
                return False
                
            self.rollback_in_progress = True
            
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
                if not self._restore_files_from_backup(backup_path):
                    raise AntivirusError("File restoration failed")
                    
                # Restore database
                if not self._restore_database_from_backup(backup_path):
                    self.logger.warning("Database restoration failed")
                    
                # Restore configuration
                if not self._restore_configuration_from_backup(backup_path):
                    self.logger.warning("Configuration restoration failed")
                    
                # Start services
                self._start_services()
                
                # Verify rollback
                if not self._verify_rollback_success(backup_path):
                    raise AntivirusError("Rollback verification failed")
                    
                # Log successful rollback
                self._log_rollback_success(backup_path)
                
                self.logger.info("Rollback completed successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"Rollback failed, attempting recovery: {e}")
                
                # Attempt to recover from rollback point
                if rollback_point and self._recover_from_rollback_point(rollback_point):
                    self.logger.info("Recovery from rollback point successful")
                else:
                    self.logger.critical("Recovery failed - manual intervention required")
                    
                raise
                
        except Exception as e:
            self.logger.error(f"Rollback operation failed: {e}")
            self._log_rollback_failure(backup_path, str(e))
            return False
            
        finally:
            self.rollback_in_progress = False
            
    def _validate_backup(self, backup_path: Path) -> bool:
        """Validate backup integrity"""
        try:
            if not backup_path.exists() or not backup_path.is_dir():
                self.logger.error(f"Backup path invalid: {backup_path}")
                return False
                
            # Check version info
            version_info_file = backup_path / "version_info.json"
            if not version_info_file.exists():
                self.logger.error("Version info missing from backup")
                return False
                
            # Validate version info
            with open(version_info_file, 'r') as f:
                version_info = json.load(f)
                
            required_fields = ['version', 'backup_date', 'python_version']
            for field in required_fields:
                if field not in version_info:
                    self.logger.error(f"Missing field in version info: {field}")
                    return False
                    
            # Check essential directories
            essential_dirs = ['src']
            for dir_name in essential_dirs:
                dir_path = backup_path / dir_name
                if not dir_path.exists() or not dir_path.is_dir():
                    self.logger.error(f"Essential directory missing: {dir_name}")
                    return False
                    
            self.logger.debug("Backup validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup validation error: {e}")
            return False
            
    def _create_rollback_point(self) -> Optional[Path]:
        """Create a rollback point before starting rollback"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rollback_point = self.backup_dir / f"rollback_point_{timestamp}"
            rollback_point.mkdir(parents=True, exist_ok=True)
            
            # Backup current state
            src_dir = self.app_root / "src"
            if src_dir.exists():
                shutil.copytree(src_dir, rollback_point / "src")
                
            # Backup configuration
            config_dir = self.app_root / "config"
            if config_dir.exists():
                shutil.copytree(config_dir, rollback_point / "config")
                
            # Save rollback info
            rollback_info = {
                'timestamp': timestamp,
                'purpose': 'rollback_point',
                'created_by': 'rollback_manager'
            }
            
            with open(rollback_point / "rollback_info.json", 'w') as f:
                json.dump(rollback_info, f, indent=2)
                
            self.logger.info(f"Rollback point created: {rollback_point}")
            return rollback_point
            
        except Exception as e:
            self.logger.error(f"Failed to create rollback point: {e}")
            return None
            
    def _restore_files_from_backup(self, backup_path: Path) -> bool:
        """Restore files from backup"""
        try:
            self.logger.info("Restoring files from backup...")
            
            # Restore source code
            backup_src = backup_path / "src"
            current_src = self.app_root / "src"
            
            if backup_src.exists():
                if current_src.exists():
                    shutil.rmtree(current_src)
                shutil.copytree(backup_src, current_src)
                self.logger.info("Source code restored")
            else:
                self.logger.warning("No source code in backup")
                
            # Restore other files
            for item in backup_path.iterdir():
                if item.name in ['src', 'config', 'data', 'version_info.json']:
                    continue
                    
                dest = self.app_root / item.name
                if item.is_file():
                    shutil.copy2(item, dest)
                elif item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                    
            return True
            
        except Exception as e:
            self.logger.error(f"File restoration failed: {e}")
            return False
            
    def _restore_database_from_backup(self, backup_path: Path) -> bool:
        """Restore database from backup"""
        try:
            backup_db = backup_path / "data" / "antivirus.db"
            current_db = self.app_root / "data" / "antivirus.db"
            
            if backup_db.exists():
                # Create data directory if it doesn't exist
                current_db.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy database file
                shutil.copy2(backup_db, current_db)
                self.logger.info("Database restored from backup")
                return True
            else:
                self.logger.warning("No database in backup")
                return True  # Not critical
                
        except Exception as e:
            self.logger.error(f"Database restoration failed: {e}")
            return False
            
    def _restore_configuration_from_backup(self, backup_path: Path) -> bool:
        """Restore configuration from backup"""
        try:
            backup_config = backup_path / "config"
            current_config = self.app_root / "config"
            
            if backup_config.exists():
                if current_config.exists():
                    shutil.rmtree(current_config)
                shutil.copytree(backup_config, current_config)
                self.logger.info("Configuration restored from backup")
            else:
                self.logger.warning("No configuration in backup")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration restoration failed: {e}")
            return False
            
    def _stop_services(self) -> None:
        """Stop antivirus services"""
        try:
            self.logger.info("Stopping services for rollback...")
            # Implementation would stop running services
            # This is platform-specific
        except Exception as e:
            self.logger.error(f"Failed to stop services: {e}")
            
    def _start_services(self) -> None:
        """Start antivirus services"""
        try:
            self.logger.info("Starting services after rollback...")
            # Implementation would start services
            # This is platform-specific
        except Exception as e:
            self.logger.error(f"Failed to start services: {e}")
            
    def _verify_rollback_success(self, backup_path: Path) -> bool:
        """Verify that rollback was successful"""
        try:
            # Check version info
            version_info_file = backup_path / "version_info.json"
            with open(version_info_file, 'r') as f:
                backup_version_info = json.load(f)
                
            expected_version = backup_version_info.get('version')
            
            # Try to import and check version
            try:
                sys.path.insert(0, str(self.app_root / "src"))
                import prashant918_antivirus
                current_version = getattr(prashant918_antivirus, '__version__', None)
                
                if current_version != expected_version:
                    self.logger.error(f"Version mismatch after rollback: {current_version} != {expected_version}")
                    return False
                    
                # Try basic import test
                from prashant918_antivirus.antivirus.engine import AdvancedThreatDetectionEngine
                
                self.logger.info("Rollback verification passed")
                return True
                
            except ImportError as e:
                self.logger.error(f"Import test failed after rollback: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Rollback verification failed: {e}")
            return False
            
    def _recover_from_rollback_point(self, rollback_point: Path) -> bool:
        """Recover from rollback point"""
        try:
            self.logger.info(f"Recovering from rollback point: {rollback_point}")
            
            # Restore from rollback point
            return self._restore_files_from_backup(rollback_point)
            
        except Exception as e:
            self.logger.error(f"Recovery from rollback point failed: {e}")
            return False
            
    def _log_rollback_success(self, backup_path: Path) -> None:
        """Log successful rollback"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'status': 'success',
                'backup_path': str(backup_path),
                'message': 'Rollback completed successfully'
            }
            
            self._write_rollback_log(log_entry)
            
        except Exception as e:
            self.logger.error(f"Failed to log rollback success: {e}")
            
    def _log_rollback_failure(self, backup_path: Path, error_message: str) -> None:
        """Log rollback failure"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'status': 'failure',
                'backup_path': str(backup_path),
                'error_message': error_message
            }
            
            self._write_rollback_log(log_entry)
            
        except Exception as e:
            self.logger.error(f"Failed to log rollback failure: {e}")
            
    def _write_rollback_log(self, log_entry: Dict) -> None:
        """Write entry to rollback log"""
        try:
            # Ensure log directory exists
            self.rollback_log.parent.mkdir(parents=True, exist_ok=True)
            
            # Append to log file
            with open(self.rollback_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            self.logger.error(f"Failed to write rollback log: {e}")
            
    def get_rollback_history(self) -> List[Dict]:
        """Get rollback history"""
        try:
            if not self.rollback_log.exists():
                return []
                
            history = []
            with open(self.rollback_log, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        history.append(entry)
                    except json.JSONDecodeError:
                        continue
                        
            return history
            
        except Exception as e:
            self.logger.error(f"Failed to read rollback history: {e}")
            return []
