"""
Version Management System
Handles version tracking, comparison, and history
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from packaging import version

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

class VersionManager:
    """Manages version information and history"""
    
    def __init__(self):
        self.logger = SecureLogger("VersionManager")
        
        # Paths
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.data_dir = Path.home() / ".prashant918_antivirus" / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.version_file = self.data_dir / "version.json"
        self.version_history_file = self.data_dir / "version_history.json"
        
        # Initialize version file if it doesn't exist
        if not self.version_file.exists():
            self._initialize_version_file()
    
    def _initialize_version_file(self):
        """Initialize version file with current version"""
        try:
            current_version = self._detect_current_version()
            
            version_info = {
                "version": current_version,
                "build_date": datetime.now().isoformat(),
                "build_type": "release",
                "commit_hash": "unknown",
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
            }
            
            with open(self.version_file, 'w') as f:
                json.dump(version_info, f, indent=2)
            
            self.logger.info(f"Initialized version file with version {current_version}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize version file: {e}")
    
    def _detect_current_version(self) -> str:
        """Detect current version from package files"""
        try:
            # Try to get version from __init__.py
            init_file = self.app_root / "src" / "prashant918_antivirus" / "__init__.py"
            if init_file.exists():
                with open(init_file, 'r') as f:
                    content = f.read()
                    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        return match.group(1)
            
            # Try to get version from setup.py
            setup_file = self.app_root / "setup.py"
            if setup_file.exists():
                with open(setup_file, 'r') as f:
                    content = f.read()
                    match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        return match.group(1)
            
            # Default version
            return "1.0.2"
            
        except Exception as e:
            self.logger.warning(f"Could not detect version: {e}")
            return "1.0.2"
    
    def get_current_version(self) -> str:
        """Get current application version"""
        try:
            with open(self.version_file, 'r') as f:
                version_info = json.load(f)
                return version_info.get("version", "1.0.2")
        except Exception as e:
            self.logger.error(f"Failed to get current version: {e}")
            return "1.0.2"
    
    def get_version_info(self) -> Dict[str, Any]:
        """Get detailed version information"""
        try:
            with open(self.version_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to get version info: {e}")
            return {"version": "1.0.2", "error": str(e)}
    
    def update_version(self, new_version: str, build_type: str = "release") -> bool:
        """Update version information"""
        try:
            version_info = {
                "version": new_version,
                "build_date": datetime.now().isoformat(),
                "build_type": build_type,
                "commit_hash": "unknown",
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
            }
            
            with open(self.version_file, 'w') as f:
                json.dump(version_info, f, indent=2)
            
            # Update version history
            self._update_version_history(new_version)
            
            self.logger.info(f"Updated version to {new_version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update version: {e}")
            return False
    
    def _update_version_history(self, new_version: str):
        """Update version history"""
        try:
            history = []
            if self.version_history_file.exists():
                with open(self.version_history_file, 'r') as f:
                    history = json.load(f)
            
            history.append({
                "version": new_version,
                "update_date": datetime.now().isoformat(),
                "update_type": "automatic"
            })
            
            # Keep only last 50 entries
            history = history[-50:]
            
            with open(self.version_history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to update version history: {e}")
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings"""
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
            self.logger.error(f"Failed to compare versions: {e}")
            # Fallback to string comparison
            if version1 < version2:
                return -1
            elif version1 > version2:
                return 1
            else:
                return 0
    
    def is_newer_version(self, new_version: str) -> bool:
        """Check if a version is newer than current"""
        current = self.get_current_version()
        return self.compare_versions(new_version, current) > 0
    
    def get_version_history(self) -> List[Dict[str, Any]]:
        """Get version update history"""
        try:
            if self.version_history_file.exists():
                with open(self.version_history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Failed to get version history: {e}")
            return []
    
    def validate_version_format(self, version_string: str) -> bool:
        """Validate version string format"""
        try:
            version.parse(version_string)
            return True
        except Exception:
            # Fallback regex validation
            pattern = r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?$'
            return bool(re.match(pattern, version_string))
    
    def get_next_version(self, update_type: str = "patch") -> str:
        """Generate next version number"""
        try:
            current = self.get_current_version()
            v = version.parse(current)
            
            if update_type == "major":
                return f"{v.major + 1}.0.0"
            elif update_type == "minor":
                return f"{v.major}.{v.minor + 1}.0"
            else:  # patch
                return f"{v.major}.{v.minor}.{v.micro + 1}"
                
        except Exception as e:
            self.logger.error(f"Failed to generate next version: {e}")
            return "1.0.3"  # Safe fallback