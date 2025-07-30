"""
Update Server Communication Module
Handles communication with update servers and version checking
"""

import json
import time
import hashlib
import requests
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading
from dataclasses import dataclass, asdict

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import NetworkError, UpdateError


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
    min_system_requirements: Dict[str, Any]
    compatibility_info: Dict[str, Any]


class UpdateServer:
    """
    Handles communication with update servers
    """
    
    def __init__(self):
        self.logger = SecureLogger("UpdateServer")
        self.config = SecureConfig()
        
        # Server configuration
        self.primary_server = self.config.get('update.primary_server', 
                                            'https://updates.prashant918.com/api/v1')
        self.fallback_servers = self.config.get('update.fallback_servers', [
            'https://backup1.prashant918.com/api/v1',
            'https://backup2.prashant918.com/api/v1'
        ])
        
        # Authentication
        self.api_key = self.config.get('update.api_key', '')
        self.client_id = self.config.get('update.client_id', self._generate_client_id())
        
        # Request settings
        self.timeout = self.config.get('update.timeout', 30)
        self.max_retries = self.config.get('update.max_retries', 3)
        self.retry_delay = self.config.get('update.retry_delay', 5)
        
        # Cache settings
        self.cache_duration = self.config.get('update.cache_duration', 3600)  # 1 hour
        self.cache_file = Path.home() / '.prashant918_antivirus' / 'update_cache.json'
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = self.config.get('update.min_request_interval', 60)
        
        # Thread safety
        self.lock = threading.Lock()
        
    def _generate_client_id(self) -> str:
        """Generate unique client ID"""
        import uuid
        import platform
        
        # Create unique ID based on system info
        system_info = f"{platform.node()}-{platform.system()}-{platform.machine()}"
        client_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, system_info))
        
        # Save to config
        self.config.set('update.client_id', client_id)
        return client_id
        
    def check_for_updates(self, current_version: str) -> Optional[UpdateInfo]:
        """Check for available updates"""
        try:
            with self.lock:
                # Check rate limiting
                current_time = time.time()
                if current_time - self.last_request_time < self.min_request_interval:
                    self.logger.info("Rate limit active, using cached data if available")
                    return self._get_cached_update_info(current_version)
                
                # Try to get update info from servers
                update_info = self._fetch_update_info(current_version)
                
                if update_info:
                    # Cache the result
                    self._cache_update_info(update_info)
                    self.last_request_time = current_time
                    
                return update_info
                
        except Exception as e:
            self.logger.error(f"Failed to check for updates: {e}")
            # Try to return cached data as fallback
            return self._get_cached_update_info(current_version)
            
    def _fetch_update_info(self, current_version: str) -> Optional[UpdateInfo]:
        """Fetch update information from servers"""
        servers = [self.primary_server] + self.fallback_servers
        
        for server_url in servers:
            try:
                self.logger.info(f"Checking for updates from {server_url}")
                
                # Prepare request data
                request_data = {
                    'current_version': current_version,
                    'client_id': self.client_id,
                    'platform': self._get_platform_info(),
                    'system_info': self._get_system_info()
                }
                
                # Make request
                response = self._make_request(
                    f"{server_url}/check-updates",
                    method='POST',
                    data=request_data
                )
                
                if response and response.get('status') == 'success':
                    update_data = response.get('data')
                    if update_data and self._is_newer_version(update_data.get('version'), current_version):
                        return UpdateInfo(**update_data)
                    else:
                        self.logger.info("No newer version available")
                        return None
                        
            except Exception as e:
                self.logger.warning(f"Failed to fetch from {server_url}: {e}")
                continue
                
        raise UpdateError("All update servers failed")
        
    def _make_request(self, url: str, method: str = 'GET', data: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retries"""
        headers = {
            'User-Agent': f'Prashant918-Antivirus-Updater/1.0',
            'Content-Type': 'application/json'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
            
        for attempt in range(self.max_retries):
            try:
                if method.upper() == 'POST':
                    response = requests.post(
                        url,
                        json=data,
                        headers=headers,
                        timeout=self.timeout,
                        verify=True
                    )
                else:
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=True
                    )
                    
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Request attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                else:
                    raise NetworkError(f"Request failed after {self.max_retries} attempts", url=url)
                    
        return None
        
    def _get_platform_info(self) -> Dict[str, str]:
        """Get platform information"""
        import platform
        
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0]
        }
        
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for compatibility checking"""
        import sys
        import psutil
        
        try:
            # Get system resources
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                'memory_total_gb': round(memory.total / (1024**3), 2),
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_free_gb': round(disk.free / (1024**3), 2),
                'cpu_count': psutil.cpu_count(),
                'cpu_freq_mhz': psutil.cpu_freq().current if psutil.cpu_freq() else None
            }
        except Exception as e:
            self.logger.warning(f"Failed to get system info: {e}")
            return {
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            }
            
    def _is_newer_version(self, new_version: str, current_version: str) -> bool:
        """Check if new version is newer than current"""
        try:
            from packaging import version
            return version.parse(new_version) > version.parse(current_version)
        except Exception:
            # Fallback to string comparison
            return new_version > current_version
            
    def _cache_update_info(self, update_info: UpdateInfo) -> None:
        """Cache update information"""
        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'update_info': asdict(update_info)
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
            self.logger.debug("Update info cached successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to cache update info: {e}")
            
    def _get_cached_update_info(self, current_version: str) -> Optional[UpdateInfo]:
        """Get cached update information if still valid"""
        try:
            if not self.cache_file.exists():
                return None
                
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
                
            # Check cache age
            cache_time = datetime.fromisoformat(cache_data['timestamp'])
            if datetime.now() - cache_time > timedelta(seconds=self.cache_duration):
                self.logger.debug("Cache expired")
                return None
                
            # Check if cached version is newer
            cached_info = UpdateInfo(**cache_data['update_info'])
            if self._is_newer_version(cached_info.version, current_version):
                self.logger.info("Using cached update info")
                return cached_info
                
        except Exception as e:
            self.logger.warning(f"Failed to read cache: {e}")
            
        return None
        
    def download_update(self, update_info: UpdateInfo, progress_callback=None) -> Optional[Path]:
        """Download update file"""
        try:
            self.logger.info(f"Downloading update {update_info.version}")
            
            # Create temporary download path
            download_dir = Path.home() / '.prashant918_antivirus' / 'downloads'
            download_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"update_{update_info.version}.zip"
            download_path = download_dir / filename
            
            # Download with progress tracking
            response = requests.get(
                update_info.download_url,
                stream=True,
                timeout=self.timeout,
                verify=True
            )
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Call progress callback
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress)
                            
            # Verify checksum
            if not self._verify_checksum(download_path, update_info.checksum):
                download_path.unlink()
                raise UpdateError("Checksum verification failed")
                
            self.logger.info(f"Update downloaded successfully: {download_path}")
            return download_path
            
        except Exception as e:
            self.logger.error(f"Failed to download update: {e}")
            raise UpdateError(f"Download failed: {e}")
            
    def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """Verify file checksum"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                    
            calculated_checksum = sha256_hash.hexdigest()
            return calculated_checksum.lower() == expected_checksum.lower()
            
        except Exception as e:
            self.logger.error(f"Checksum verification failed: {e}")
            return False
            
    def report_update_status(self, update_info: UpdateInfo, status: str, error_message: str = None) -> bool:
        """Report update status back to server"""
        try:
            report_data = {
                'client_id': self.client_id,
                'version': update_info.version,
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'error_message': error_message,
                'system_info': self._get_system_info()
            }
            
            response = self._make_request(
                f"{self.primary_server}/report-update",
                method='POST',
                data=report_data
            )
            
            return response and response.get('status') == 'success'
            
        except Exception as e:
            self.logger.warning(f"Failed to report update status: {e}")
            return False
