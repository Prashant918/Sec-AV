"""
Automated Upgrade System for Prashant918 Advanced Antivirus
Handles self-upgrading without human intervention
"""

import os
import sys
import json
import time
import shutil
import hashlib
import requests
import subprocess
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import threading
import logging
from dataclasses import dataclass

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import AntivirusError
from .version_manager import VersionManager
from .dependency_updater import DependencyUpdater
from .update_server import UpdateServer
from .integrity_checker import IntegrityChecker
from .rollback_manager import RollbackManager
from .config_migrator import ConfigMigrator


@dataclass
class UpdateInfo:
    """Information about available updates"""
    version: str
    release_date: str
    download_url: str
    checksum: str
    size: int
    critical: bool
    changelog: str
    dependencies: Dict[str, str]


class AutoUpgrader:
    """
    Automated upgrade system that handles:
    - Version checking
    - Downloading updates
    - Applying patches
    - Rolling back on failure
    - Dependency management
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = SecureConfig(config_path)
        self.logger = SecureLogger("AutoUpgrader")
        self.version_manager = VersionManager()
        self.dependency_updater = DependencyUpdater()
        self.update_server = UpdateServer()
        self.integrity_checker = IntegrityChecker()
        self.rollback_manager = RollbackManager()
        self.config_migrator = ConfigMigrator()
        
        # Upgrade settings
        self.update_check_interval = self.config.get('upgrade.check_interval', 3600)  # 1 hour
        self.auto_update_enabled = self.config.get('upgrade.auto_update', True)
        self.critical_updates_only = self.config.get('upgrade.critical_only', False)
        self.backup_before_update = self.config.get('upgrade.backup_enabled', True)
        self.max_rollback_versions = self.config.get('upgrade.max_rollbacks', 3)
        
        # Paths
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.backup_dir = self.app_root / "backups"
        self.temp_dir = self.app_root / "temp" / "updates"
        self.update_log = self.app_root / "logs" / "updates.log"
        
        # Create directories
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Update state
        self.is_updating = False
        self.last_check = None
        self.update_thread = None
        
    def start_auto_updater(self) -> None:
        """Start the automatic update checker in background"""
        if self.update_thread and self.update_thread.is_alive():
            self.logger.warning("Auto-updater already running")
            return
            
        self.logger.info("Starting automatic update checker")
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
    def stop_auto_updater(self) -> None:
        """Stop the automatic update checker"""
        self.logger.info("Stopping automatic update checker")
        # Implementation would set a stop flag for the update loop
        
    def _update_loop(self) -> None:
        """Main update checking loop"""
        while True:
            try:
                if self.auto_update_enabled and not self.is_updating:
                    self.check_and_apply_updates()
                    
                time.sleep(self.update_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in update loop: {e}")
                time.sleep(300)  # Wait 5 minutes on error
                
    def check_and_apply_updates(self) -> bool:
        """Check for updates and apply them if available"""
        try:
            self.logger.info("Checking for updates...")
            
            # Get current version
            current_version = self.version_manager.get_current_version()
            
            # Check for available updates
            update_info = self.update_server.check_for_updates(current_version)
            
            if not update_info:
                self.logger.info("No updates available")
                self.last_check = datetime.now()
                return False
                
            # Filter updates based on settings
            if self.critical_updates_only and not update_info.critical:
                self.logger.info(f"Non-critical update {update_info.version} skipped")
                return False
                
            self.logger.info(f"Update available: {update_info.version}")
            
            # Apply the update
            return self.apply_update(update_info)
            
        except Exception as e:
            self.logger.error(f"Failed to check for updates: {e}")
            return False
            
    def apply_update(self, update_info: UpdateInfo) -> bool:
        """Apply a specific update"""
        if self.is_updating:
            self.logger.warning("Update already in progress")
            return False
            
        self.is_updating = True
        update_success = False
        backup_path = None
        
        try:
            self.logger.info(f"Starting update to version {update_info.version}")
            
            # Create backup if enabled
            if self.backup_before_update:
                backup_path = self._create_backup()
                if not backup_path:
                    raise AntivirusError("Failed to create backup")
                    
            # Download update
            update_file = self._download_update(update_info)
            if not update_file:
                raise AntivirusError("Failed to download update")
                
            # Verify integrity
            if not self.integrity_checker.verify_update(update_file, update_info.checksum):
                raise AntivirusError("Update integrity verification failed")
                
            # Stop services before update
            self._stop_services()
            
            # Apply the update
            self._apply_update_files(update_file, update_info)
            
            # Update dependencies
            self.dependency_updater.update_dependencies(update_info.dependencies)
            
            # Migrate configuration
            self.config_migrator.migrate_config(
                self.version_manager.get_current_version(),
                update_info.version
            )
            
            # Update version info
            self.version_manager.update_version(update_info.version)
            
            # Restart services
            self._start_services()
            
            # Verify update success
            if self._verify_update_success(update_info.version):
                update_success = True
                self.logger.info(f"Successfully updated to version {update_info.version}")
                
                # Clean up old backups
                self._cleanup_old_backups()
                
            else:
                raise AntivirusError("Update verification failed")
                
        except Exception as e:
            self.logger.error(f"Update failed: {e}")
            
            # Attempt rollback
            if backup_path:
                self.logger.info("Attempting rollback...")
                if self.rollback_manager.rollback_from_backup(backup_path):
                    self.logger.info("Rollback successful")
                else:
                    self.logger.error("Rollback failed - manual intervention required")
                    
        finally:
            self.is_updating = False
            self._cleanup_temp_files()
            
        return update_success
        
    def _create_backup(self) -> Optional[Path]:
        """Create a backup of the current installation"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            current_version = self.version_manager.get_current_version()
            backup_name = f"backup_v{current_version}_{timestamp}"
            backup_path = self.backup_dir / backup_name
            
            self.logger.info(f"Creating backup: {backup_path}")
            
            # Create backup directory
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Copy application files
            shutil.copytree(
                self.app_root / "src",
                backup_path / "src",
                ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.log')
            )
            
            # Copy configuration
            config_dir = self.app_root / "config"
            if config_dir.exists():
                shutil.copytree(config_dir, backup_path / "config")
                
            # Copy database
            db_file = self.app_root / "data" / "antivirus.db"
            if db_file.exists():
                backup_path.mkdir(parents=True, exist_ok=True)
                shutil.copy2(db_file, backup_path / "data" / "antivirus.db")
                
            # Save version info
            version_info = {
                'version': current_version,
                'backup_date': timestamp,
                'python_version': sys.version,
                'platform': sys.platform
            }
            
            with open(backup_path / "version_info.json", 'w') as f:
                json.dump(version_info, f, indent=2)
                
            self.logger.info(f"Backup created successfully: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return None
            
    def _download_update(self, update_info: UpdateInfo) -> Optional[Path]:
        """Download update file"""
        try:
            self.logger.info(f"Downloading update from {update_info.download_url}")
            
            update_file = self.temp_dir / f"update_{update_info.version}.zip"
            
            response = requests.get(update_info.download_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(update_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Log progress
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if downloaded % (1024 * 1024) == 0:  # Log every MB
                                self.logger.info(f"Download progress: {progress:.1f}%")
                                
            self.logger.info(f"Update downloaded: {update_file}")
            return update_file
            
        except Exception as e:
            self.logger.error(f"Failed to download update: {e}")
            return None
            
    def _apply_update_files(self, update_file: Path, update_info: UpdateInfo) -> None:
        """Extract and apply update files"""
        import zipfile
        
        self.logger.info("Applying update files...")
        
        with zipfile.ZipFile(update_file, 'r') as zip_ref:
            # Extract to temporary directory
            extract_dir = self.temp_dir / "extracted"
            zip_ref.extractall(extract_dir)
            
            # Copy files to application directory
            src_dir = extract_dir / "src"
            if src_dir.exists():
                # Remove old files
                app_src = self.app_root / "src"
                if app_src.exists():
                    shutil.rmtree(app_src)
                    
                # Copy new files
                shutil.copytree(src_dir, app_src)
                
            # Update other files as needed
            for item in extract_dir.iterdir():
                if item.name not in ['src']:
                    dest = self.app_root / item.name
                    if item.is_file():
                        shutil.copy2(item, dest)
                    elif item.is_dir():
                        if dest.exists():
                            shutil.rmtree(dest)
                        shutil.copytree(item, dest)
                        
    def _stop_services(self) -> None:
        """Stop antivirus services before update"""
        try:
            self.logger.info("Stopping antivirus services...")
            # Implementation would stop running services
            # This is platform-specific
            pass
        except Exception as e:
            self.logger.error(f"Failed to stop services: {e}")
            
    def _start_services(self) -> None:
        """Start antivirus services after update"""
        try:
            self.logger.info("Starting antivirus services...")
            # Implementation would start services
            # This is platform-specific
            pass
        except Exception as e:
            self.logger.error(f"Failed to start services: {e}")
            
    def _verify_update_success(self, expected_version: str) -> bool:
        """Verify that the update was successful"""
        try:
            # Check version
            current_version = self.version_manager.get_current_version()
            if current_version != expected_version:
                return False
                
            # Try to import main modules
            try:
                from ..engine import AdvancedThreatDetectionEngine
                from ..ml_detector import EnsembleMLDetector
                # Basic functionality test
                engine = AdvancedThreatDetectionEngine()
                return True
            except ImportError as e:
                self.logger.error(f"Import test failed: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Update verification failed: {e}")
            return False
            
    def _cleanup_old_backups(self) -> None:
        """Clean up old backup files"""
        try:
            backups = sorted(self.backup_dir.glob("backup_*"), key=os.path.getctime, reverse=True)
            
            # Keep only the most recent backups
            for backup in backups[self.max_rollback_versions:]:
                self.logger.info(f"Removing old backup: {backup}")
                shutil.rmtree(backup)
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old backups: {e}")
            
    def _cleanup_temp_files(self) -> None:
        """Clean up temporary files"""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.temp_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to cleanup temp files: {e}")
            
    def get_update_status(self) -> Dict:
        """Get current update status"""
        return {
            'is_updating': self.is_updating,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'current_version': self.version_manager.get_current_version(),
            'auto_update_enabled': self.auto_update_enabled,
            'critical_updates_only': self.critical_updates_only
        }
        
    def force_update_check(self) -> bool:
        """Force an immediate update check"""
        self.logger.info("Forcing update check...")
        return self.check_and_apply_updates()
