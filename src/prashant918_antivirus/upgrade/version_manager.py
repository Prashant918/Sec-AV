"""
Version Management System
Handles version tracking, comparison, and metadata
"""

import json
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime
from packaging import version

from ..logger import SecureLogger
from ..exceptions import AntivirusError


class VersionManager:
    """
    Manages application version information and comparisons
    """
    
    def __init__(self):
        self.logger = SecureLogger("VersionManager")
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.version_file = self.app_root / "version.json"
        self.version_history_file = self.app_root / "data" / "version_history.json"
        
        # Ensure data directory exists
        self.version_history_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize version file if it doesn't exist
        self._initialize_version_file()
        
    def _initialize_version_file(self) -> None:
        """Initialize version file with current version"""
        if not self.version_file.exists():
            # Try to get version from setup.py or __init__.py
            current_version = self._detect_current_version()
            
            version_data = {
                'version': current_version,
                'build_date': datetime.now().isoformat(),
                'build_type': 'release',
                'commit_hash': None,
                'python_version': None
            }
            
            with open(self.version_file, 'w') as f:
                json.dump(version_data, f, indent=2)
                
            self.logger.info(f"Initialized version file with version {current_version}")
            
    def _detect_current_version(self) -> str:
        """Detect current version from various sources"""
        # Try to get from __init__.py
        init_file = self.app_root / "src" / "prashant918_antivirus" / "__init__.py"
        if init_file.exists():
            try:
                with open(init_file, 'r') as f:
                    content = f.read()
                    
                # Look for __version__ = "x.x.x"
                version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                if version_match:
                    return version_match.group(1)
                    
            except Exception as e:
                self.logger.warning(f"Failed to read version from __init__.py: {e}")
                
        # Try to get from setup.py
        setup_file = self.app_root / "setup.py"
        if setup_file.exists():
            try:
                with open(setup_file, 'r') as f:
                    content = f.read()
                    
                # Look for version="x.x.x"
                version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if version_match:
                    return version_match.group(1)
                    
            except Exception as e:
                self.logger.warning(f"Failed to read version from setup.py: {e}")
                
        # Default version
        return "1.0.0"
        
    def get_current_version(self) -> str:
        """Get the current application version"""
        try:
            with open(self.version_file, 'r') as f:
                version_data = json.load(f)
                return version_data.get('version', '1.0.0')
        except Exception as e:
            self.logger.error(f"Failed to read version file: {e}")
            return "1.0.0"
            
    def get_version_info(self) -> Dict:
        """Get detailed version information"""
        try:
            with open(self.version_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to read version info: {e}")
            return {'version': '1.0.0'}
            
    def update_version(self, new_version: str, build_type: str = 'release') -> None:
        """Update the version information"""
        try:
            # Get current version info
            current_info = self.get_version_info()
            old_version = current_info.get('version', '1.0.0')
            
            # Create new version info
            new_info = {
                'version': new_version,
                'build_date': datetime.now().isoformat(),
                'build_type': build_type,
                'commit_hash': None,
                'python_version': None,
                'previous_version': old_version
            }
            
            # Write new version file
            with open(self.version_file, 'w') as f:
                json.dump(new_info, f, indent=2)
                
            # Update version history
            self._update_version_history(old_version, new_version)
            
            self.logger.info(f"Updated version from {old_version} to {new_version}")
            
        except Exception as e:
            self.logger.error(f"Failed to update version: {e}")
            raise AntivirusError(f"Version update failed: {e}")
            
    def _update_version_history(self, old_version: str, new_version: str) -> None:
        """Update the version history log"""
        try:
            # Load existing history
            history = []
            if self.version_history_file.exists():
                with open(self.version_history_file, 'r') as f:
                    history = json.load(f)
                    
            # Add new entry
            history_entry = {
                'from_version': old_version,
                'to_version': new_version,
                'update_date': datetime.now().isoformat(),
                'update_type': 'automatic' if old_version != '1.0.0' else 'initial'
            }
            
            history.append(history_entry)
            
            # Keep only last 50 entries
            history = history[-50:]
            
            # Save updated history
            with open(self.version_history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to update version history: {e}")
            
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1 = version.parse(version1)
            v2 = version.parse(version2)
            
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0
                
        except Exception as e:
            self.logger.error(f"Failed to compare versions {version1} and {version2}: {e}")
            return 0
            
    def is_newer_version(self, new_version: str, current_version: Optional[str] = None) -> bool:
        """Check if a version is newer than the current version"""
        if current_version is None:
            current_version = self.get_current_version()
            
        return self.compare_versions(new_version, current_version) > 0
        
    def get_version_history(self) -> List[Dict]:
        """Get the version update history"""
        try:
            if self.version_history_file.exists():
                with open(self.version_history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Failed to read version history: {e}")
            return []
            
    def validate_version_format(self, version_string: str) -> bool:
        """Validate version string format"""
        try:
            version.parse(version_string)
            return True
        except Exception:
            return False
            
    def get_next_version(self, current_version: str, update_type: str = 'patch') -> str:
        """Generate next version number based on update type"""
        try:
            v = version.parse(current_version)
            
            if update_type == 'major':
                return f"{v.major + 1}.0.0"
            elif update_type == 'minor':
                return f"{v.major}.{v.minor + 1}.0"
            else:  # patch
                return f"{v.major}.{v.minor}.{v.micro + 1}"
                
        except Exception as e:
            self.logger.error(f"Failed to generate next version: {e}")
            return current_version
