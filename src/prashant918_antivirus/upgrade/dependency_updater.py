"""
Dependency Update Manager
Handles automatic updating of Python packages and system dependencies
"""

import subprocess
import sys
import json
import pkg_resources
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests
from packaging import version

from ..logger import SecureLogger
from ..exceptions import AntivirusError


class DependencyUpdater:
    """
    Manages automatic updating of dependencies
    """
    
    def __init__(self):
        self.logger = SecureLogger("DependencyUpdater")
        self.app_root = Path(__file__).parent.parent.parent.parent
        self.requirements_file = self.app_root / "requirements.txt"
        self.dependency_lock_file = self.app_root / "dependency_lock.json"
        
    def update_dependencies(self, new_requirements: Dict[str, str]) -> bool:
        """Update dependencies to specified versions"""
        try:
            self.logger.info("Starting dependency update...")
            
            # Create backup of current dependencies
            current_deps = self._get_current_dependencies()
            self._backup_dependencies(current_deps)
            
            # Update each dependency
            failed_updates = []
            for package, target_version in new_requirements.items():
                try:
                    if not self._update_single_package(package, target_version):
                        failed_updates.append(package)
                except Exception as e:
                    self.logger.error(f"Failed to update {package}: {e}")
                    failed_updates.append(package)
                    
            if failed_updates:
                self.logger.warning(f"Failed to update packages: {failed_updates}")
                return False
                
            # Update requirements.txt
            self._update_requirements_file(new_requirements)
            
            # Update dependency lock file
            self._update_dependency_lock()
            
            self.logger.info("Dependency update completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Dependency update failed: {e}")
            return False
            
    def _get_current_dependencies(self) -> Dict[str, str]:
        """Get currently installed package versions"""
        dependencies = {}
        
        try:
            installed_packages = [d for d in pkg_resources.working_set]
            for package in installed_packages:
                dependencies[package.project_name.lower()] = package.version
                
        except Exception as e:
            self.logger.error(f"Failed to get current dependencies: {e}")
            
        return dependencies
        
    def _backup_dependencies(self, dependencies: Dict[str, str]) -> None:
        """Backup current dependency state"""
        try:
            backup_file = self.app_root / "dependency_backup.json"
            
            backup_data = {
                'timestamp': str(datetime.now()),
                'dependencies': dependencies,
                'python_version': sys.version
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
                
            self.logger.info(f"Dependencies backed up to {backup_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to backup dependencies: {e}")
            
    def _update_single_package(self, package: str, target_version: str) -> bool:
        """Update a single package to target version"""
        try:
            self.logger.info(f"Updating {package} to version {target_version}")
            
            # Check if package is already at target version
            try:
                current_version = pkg_resources.get_distribution(package).version
                if current_version == target_version:
                    self.logger.info(f"{package} already at version {target_version}")
                    return True
            except pkg_resources.DistributionNotFound:
                self.logger.info(f"{package} not currently installed")
                
            # Install/upgrade the package
            cmd = [
                sys.executable, "-m", "pip", "install", 
                f"{package}=={target_version}", "--upgrade"
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"Successfully updated {package} to {target_version}")
                return True
            else:
                self.logger.error(f"Failed to update {package}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout updating {package}")
            return False
        except Exception as e:
            self.logger.error(f"Error updating {package}: {e}")
            return False
            
    def _update_requirements_file(self, new_requirements: Dict[str, str]) -> None:
        """Update the requirements.txt file"""
        try:
            if not self.requirements_file.exists():
                self.logger.warning("requirements.txt not found, creating new one")
                
            # Read existing requirements
            existing_requirements = {}
            if self.requirements_file.exists():
                with open(self.requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '==' in line:
                                package, ver = line.split('==', 1)
                                existing_requirements[package.strip()] = ver.strip()
                            else:
                                existing_requirements[line] = None
                                
            # Update with new requirements
            existing_requirements.update(new_requirements)
            
            # Write updated requirements
            with open(self.requirements_file, 'w') as f:
                f.write("# Auto-generated requirements file\n")
                f.write(f"# Updated: {datetime.now().isoformat()}\n\n")
                
                for package, ver in sorted(existing_requirements.items()):
                    if ver:
                        f.write(f"{package}=={ver}\n")
                    else:
                        f.write(f"{package}\n")
                        
            self.logger.info("Updated requirements.txt")
            
        except Exception as e:
            self.logger.error(f"Failed to update requirements.txt: {e}")
            
    def _update_dependency_lock(self) -> None:
        """Update dependency lock file with current state"""
        try:
            current_deps = self._get_current_dependencies()
            
            lock_data = {
                'timestamp': datetime.now().isoformat(),
                'python_version': sys.version,
                'platform': sys.platform,
                'dependencies': current_deps
            }
            
            with open(self.dependency_lock_file, 'w') as f:
                json.dump(lock_data, f, indent=2)
                
            self.logger.info("Updated dependency lock file")
            
        except Exception as e:
            self.logger.error(f"Failed to update dependency lock: {e}")
            
    def check_for_security_updates(self) -> List[Dict]:
        """Check for security updates in dependencies"""
        security_updates = []
        
        try:
            # Get current dependencies
            current_deps = self._get_current_dependencies()
            
            # Check each dependency for security advisories
            for package, current_version in current_deps.items():
                try:
                    advisories = self._check_package_security(package, current_version)
                    if advisories:
                        security_updates.extend(advisories)
                except Exception as e:
                    self.logger.warning(f"Failed to check security for {package}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to check for security updates: {e}")
            
        return security_updates
        
    def _check_package_security(self, package: str, current_version: str) -> List[Dict]:
        """Check a specific package for security advisories"""
        advisories = []
        
        try:
            # Use PyPI JSON API to get package info
            url = f"https://pypi.org/pypi/{package}/json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if there are newer versions
                releases = data.get('releases', {})
                latest_version = data.get('info', {}).get('version', current_version)
                
                if version.parse(latest_version) > version.parse(current_version):
                    # This is a simplified check - in reality, you'd want to
                    # integrate with security databases like OSV, Snyk, etc.
                    advisories.append({
                        'package': package,
                        'current_version': current_version,
                        'latest_version': latest_version,
                        'severity': 'info',
                        'description': f'Newer version available: {latest_version}'
                    })
                    
        except Exception as e:
            self.logger.warning(f"Failed to check security for {package}: {e}")
            
        return advisories
        
    def rollback_dependencies(self) -> bool:
        """Rollback dependencies to previous state"""
        try:
            backup_file = self.app_root / "dependency_backup.json"
            
            if not backup_file.exists():
                self.logger.error("No dependency backup found")
                return False
                
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
                
            previous_deps = backup_data.get('dependencies', {})
            
            self.logger.info("Rolling back dependencies...")
            
            # Rollback each dependency
            for package, target_version in previous_deps.items():
                try:
                    self._update_single_package(package, target_version)
                except Exception as e:
                    self.logger.error(f"Failed to rollback {package}: {e}")
                    
            self.logger.info("Dependency rollback completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Dependency rollback failed: {e}")
            return False
