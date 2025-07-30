"""
Configuration Migration Manager
Handles configuration migration between different versions
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import re

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import AntivirusError, ValidationError


class ConfigMigrator:
    """
    Manages configuration migration between versions
    """
    
    def __init__(self):
        self.logger = SecureLogger("ConfigMigrator")
        self.config = SecureConfig()
        
        # Paths
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.config_dir = self.app_root / "config"
        self.migration_log = self.app_root / "logs" / "config_migration.log"
        
        # Migration rules
        self.migration_rules = self._load_migration_rules()
        
    def _load_migration_rules(self) -> Dict[str, Dict]:
        """Load configuration migration rules"""
        return {
            "1.0.0_to_1.0.1": {
                "renamed_keys": {
                    "scan.max_file_size": "scanning.max_file_size_mb",
                    "update.check_interval": "upgrade.check_interval_hours"
                },
                "removed_keys": [
                    "deprecated.old_setting",
                    "legacy.feature_flag"
                ],
                "new_keys": {
                    "scanning.parallel_threads": 4,
                    "upgrade.auto_restart": True
                },
                "value_transformations": {
                    "scanning.max_file_size_mb": lambda x: x / (1024 * 1024) if isinstance(x, int) else x,
                    "upgrade.check_interval_hours": lambda x: x / 3600 if isinstance(x, int) else x
                }
            },
            "1.0.1_to_1.0.2": {
                "renamed_keys": {
                    "ml.threshold": "detection.ml_threshold",
                    "quarantine.max_size": "quarantine.max_size_gb"
                },
                "removed_keys": [
                    "experimental.beta_feature"
                ],
                "new_keys": {
                    "detection.behavioral_analysis": True,
                    "system.adaptive_performance": True
                },
                "value_transformations": {
                    "quarantine.max_size_gb": lambda x: x / (1024**3) if isinstance(x, int) else x
                }
            },
            "1.0.2_to_2.0.0": {
                "renamed_keys": {
                    "engine.yara_rules_path": "detection.yara_rules_directory",
                    "database.type": "storage.database_type"
                },
                "removed_keys": [
                    "legacy.compatibility_mode",
                    "old.feature_toggle"
                ],
                "new_keys": {
                    "system.device_adaptation": True,
                    "performance.auto_scaling": True,
                    "security.enhanced_encryption": True
                },
                "structural_changes": {
                    "flatten_detection_config": True,
                    "reorganize_system_settings": True
                }
            }
        }
        
    def migrate_config(self, from_version: str, to_version: str) -> bool:
        """Migrate configuration from one version to another"""
        try:
            self.logger.info(f"Starting configuration migration from {from_version} to {to_version}")
            
            # Create backup of current configuration
            backup_path = self._backup_current_config()
            if not backup_path:
                raise AntivirusError("Failed to backup current configuration")
                
            # Get migration path
            migration_path = self._get_migration_path(from_version, to_version)
            if not migration_path:
                self.logger.info("No migration needed - versions are compatible")
                return True
                
            # Load current configuration
            current_config = self._load_current_config()
            if not current_config:
                raise AntivirusError("Failed to load current configuration")
                
            # Apply migrations step by step
            migrated_config = current_config.copy()
            for step in migration_path:
                migrated_config = self._apply_migration_step(migrated_config, step)
                
            # Validate migrated configuration
            if not self._validate_migrated_config(migrated_config, to_version):
                raise ValidationError("Migrated configuration validation failed")
                
            # Save migrated configuration
            if not self._save_migrated_config(migrated_config):
                raise AntivirusError("Failed to save migrated configuration")
                
            # Log successful migration
            self._log_migration_success(from_version, to_version, backup_path)
            
            self.logger.info(f"Configuration migration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration migration failed: {e}")
            
            # Attempt to restore from backup
            if 'backup_path' in locals() and backup_path:
                self._restore_from_backup(backup_path)
                
            return False
            
    def _backup_current_config(self) -> Optional[Path]:
        """Create backup of current configuration"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = self.app_root / "backups" / "config"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            backup_path = backup_dir / f"config_backup_{timestamp}"
            
            if self.config_dir.exists():
                shutil.copytree(self.config_dir, backup_path)
                self.logger.info(f"Configuration backed up to: {backup_path}")
                return backup_path
            else:
                self.logger.warning("No configuration directory found to backup")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to backup configuration: {e}")
            return None
            
    def _get_migration_path(self, from_version: str, to_version: str) -> List[str]:
        """Get the migration path between versions"""
        try:
            # Simple version comparison for now
            # In a real implementation, this would handle complex version trees
            
            available_migrations = list(self.migration_rules.keys())
            migration_path = []
            
            # Find direct migration
            direct_migration = f"{from_version}_to_{to_version}"
            if direct_migration in available_migrations:
                return [direct_migration]
                
            # Find step-by-step migration path
            current_version = from_version
            while current_version != to_version:
                found_next = False
                
                for migration in available_migrations:
                    if migration.startswith(f"{current_version}_to_"):
                        next_version = migration.split("_to_")[1]
                        migration_path.append(migration)
                        current_version = next_version
                        found_next = True
                        break
                        
                if not found_next:
                    self.logger.warning(f"No migration path found from {current_version} to {to_version}")
                    break
                    
            return migration_path if current_version == to_version else []
            
        except Exception as e:
            self.logger.error(f"Failed to determine migration path: {e}")
            return []
            
    def _load_current_config(self) -> Optional[Dict]:
        """Load current configuration"""
        try:
            config_data = {}
            
            # Load main configuration file
            main_config_file = self.config_dir / "config.json"
            if main_config_file.exists():
                with open(main_config_file, 'r') as f:
                    config_data.update(json.load(f))
                    
            # Load additional configuration files
            for config_file in self.config_dir.glob("*.json"):
                if config_file.name != "config.json":
                    try:
                        with open(config_file, 'r') as f:
                            section_name = config_file.stem
                            config_data[section_name] = json.load(f)
                    except Exception as e:
                        self.logger.warning(f"Failed to load {config_file}: {e}")
                        
            return config_data if config_data else None
            
        except Exception as e:
            self.logger.error(f"Failed to load current configuration: {e}")
            return None
            
    def _apply_migration_step(self, config: Dict, migration_step: str) -> Dict:
        """Apply a single migration step"""
        try:
            self.logger.info(f"Applying migration step: {migration_step}")
            
            rules = self.migration_rules.get(migration_step, {})
            migrated_config = config.copy()
            
            # Apply key renames
            renamed_keys = rules.get("renamed_keys", {})
            for old_key, new_key in renamed_keys.items():
                value = self._get_nested_value(migrated_config, old_key)
                if value is not None:
                    self._set_nested_value(migrated_config, new_key, value)
                    self._remove_nested_key(migrated_config, old_key)
                    self.logger.debug(f"Renamed key: {old_key} -> {new_key}")
                    
            # Remove deprecated keys
            removed_keys = rules.get("removed_keys", [])
            for key in removed_keys:
                if self._remove_nested_key(migrated_config, key):
                    self.logger.debug(f"Removed deprecated key: {key}")
                    
            # Add new keys with default values
            new_keys = rules.get("new_keys", {})
            for key, default_value in new_keys.items():
                if self._get_nested_value(migrated_config, key) is None:
                    self._set_nested_value(migrated_config, key, default_value)
                    self.logger.debug(f"Added new key: {key} = {default_value}")
                    
            # Apply value transformations
            transformations = rules.get("value_transformations", {})
            for key, transform_func in transformations.items():
                value = self._get_nested_value(migrated_config, key)
                if value is not None:
                    try:
                        new_value = transform_func(value)
                        self._set_nested_value(migrated_config, key, new_value)
                        self.logger.debug(f"Transformed value for {key}: {value} -> {new_value}")
                    except Exception as e:
                        self.logger.warning(f"Failed to transform value for {key}: {e}")
                        
            # Apply structural changes
            structural_changes = rules.get("structural_changes", {})
            if structural_changes:
                migrated_config = self._apply_structural_changes(migrated_config, structural_changes)
                
            return migrated_config
            
        except Exception as e:
            self.logger.error(f"Failed to apply migration step {migration_step}: {e}")
            return config
            
    def _get_nested_value(self, config: Dict, key_path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        try:
            keys = key_path.split('.')
            value = config
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
                    
            return value
            
        except Exception:
            return None
            
    def _set_nested_value(self, config: Dict, key_path: str, value: Any) -> None:
        """Set value in nested dictionary using dot notation"""
        try:
            keys = key_path.split('.')
            current = config
            
            # Navigate to the parent of the target key
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
                
            # Set the final value
            current[keys[-1]] = value
            
        except Exception as e:
            self.logger.error(f"Failed to set nested value {key_path}: {e}")
            
    def _remove_nested_key(self, config: Dict, key_path: str) -> bool:
        """Remove key from nested dictionary using dot notation"""
        try:
            keys = key_path.split('.')
            current = config
            
            # Navigate to the parent of the target key
            for key in keys[:-1]:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return False
                    
            # Remove the final key
            if isinstance(current, dict) and keys[-1] in current:
                del current[keys[-1]]
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to remove nested key {key_path}: {e}")
            return False
            
    def _apply_structural_changes(self, config: Dict, changes: Dict) -> Dict:
        """Apply structural changes to configuration"""
        try:
            modified_config = config.copy()
            
            # Flatten detection config
            if changes.get("flatten_detection_config"):
                detection_config = modified_config.get("detection", {})
                if isinstance(detection_config, dict):
                    # Move nested detection settings to top level
                    for key, value in detection_config.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                modified_config[f"detection.{key}.{sub_key}"] = sub_value
                                
            # Reorganize system settings
            if changes.get("reorganize_system_settings"):
                system_config = modified_config.get("system", {})
                if isinstance(system_config, dict):
                    # Group related settings
                    performance_settings = {}
                    security_settings = {}
                    
                    for key, value in system_config.items():
                        if any(perf_key in key.lower() for perf_key in ['performance', 'thread', 'cache', 'memory']):
                            performance_settings[key] = value
                        elif any(sec_key in key.lower() for sec_key in ['security', 'encryption', 'auth']):
                            security_settings[key] = value
                            
                    if performance_settings:
                        modified_config["performance"] = performance_settings
                    if security_settings:
                        modified_config["security"] = security_settings
                        
            return modified_config
            
        except Exception as e:
            self.logger.error(f"Failed to apply structural changes: {e}")
            return config
            
    def _validate_migrated_config(self, config: Dict, target_version: str) -> bool:
        """Validate migrated configuration"""
        try:
            # Basic validation
            if not isinstance(config, dict):
                self.logger.error("Configuration is not a dictionary")
                return False
                
            # Check for required keys based on version
            required_keys = self._get_required_keys_for_version(target_version)
            for key in required_keys:
                if self._get_nested_value(config, key) is None:
                    self.logger.error(f"Required key missing after migration: {key}")
                    return False
                    
            # Validate value types
            if not self._validate_config_types(config):
                return False
                
            self.logger.debug("Configuration validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
            
    def _get_required_keys_for_version(self, version: str) -> List[str]:
        """Get required configuration keys for a specific version"""
        # This would be defined based on the application's requirements
        base_keys = [
            "logging.level",
            "scanning.enabled",
            "quarantine.directory"
        ]
        
        # Add version-specific required keys
        if version >= "2.0.0":
            base_keys.extend([
                "system.device_adaptation",
                "performance.auto_scaling"
            ])
            
        return base_keys
        
    def _validate_config_types(self, config: Dict) -> bool:
        """Validate configuration value types"""
        try:
            type_rules = {
                "logging.level": str,
                "scanning.enabled": bool,
                "scanning.max_file_size_mb": (int, float),
                "quarantine.max_size_gb": (int, float),
                "upgrade.check_interval_hours": (int, float),
                "system.device_adaptation": bool,
                "performance.auto_scaling": bool
            }
            
            for key, expected_type in type_rules.items():
                value = self._get_nested_value(config, key)
                if value is not None and not isinstance(value, expected_type):
                    self.logger.error(f"Invalid type for {key}: expected {expected_type}, got {type(value)}")
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Type validation failed: {e}")
            return False
            
    def _save_migrated_config(self, config: Dict) -> bool:
        """Save migrated configuration"""
        try:
            # Ensure config directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Save main configuration
            main_config_file = self.config_dir / "config.json"
            with open(main_config_file, 'w') as f:
                json.dump(config, f, indent=2, sort_keys=True)
                
            # Set secure permissions
            main_config_file.chmod(0o600)
            
            self.logger.info("Migrated configuration saved successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save migrated configuration: {e}")
            return False
            
    def _restore_from_backup(self, backup_path: Path) -> bool:
        """Restore configuration from backup"""
        try:
            if backup_path.exists() and self.config_dir.exists():
                shutil.rmtree(self.config_dir)
                
            shutil.copytree(backup_path, self.config_dir)
            self.logger.info(f"Configuration restored from backup: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore from backup: {e}")
            return False
            
    def _log_migration_success(self, from_version: str, to_version: str, backup_path: Path) -> None:
        """Log successful migration"""
        try:
            # Ensure log directory exists
            self.migration_log.parent.mkdir(parents=True, exist_ok=True)
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'from_version': from_version,
                'to_version': to_version,
                'backup_path': str(backup_path),
                'status': 'success'
            }
            
            with open(self.migration_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            self.logger.error(f"Failed to log migration success: {e}")
            
    def get_migration_history(self) -> List[Dict]:
        """Get configuration migration history"""
        try:
            if not self.migration_log.exists():
                return []
                
            history = []
            with open(self.migration_log, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        history.append(entry)
                    except json.JSONDecodeError:
                        continue
                        
            return history
            
        except Exception as e:
            self.logger.error(f"Failed to read migration history: {e}")
            return []
