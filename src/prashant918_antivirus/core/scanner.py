"""
File Scanner - Core file scanning functionality
"""
import os
import time
from pathlib import Path
from typing import Dict, Any, Generator, List, Optional

try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..exceptions import AntivirusError, ScanError
except ImportError:
    class AntivirusError(Exception):
        pass
    class ScanError(AntivirusError):
        pass

class FileScanner:
    """
    Core file scanner that handles file and directory scanning
    """
    
    def __init__(self, threat_engine=None):
        self.logger = SecureLogger("FileScanner")
        self.threat_engine = threat_engine
        
        # Scannable file extensions
        self.scan_extensions = {
            '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.bat', '.cmd',
            '.vbs', '.js', '.jar', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.ppt', '.pptx', '.zip', '.rar', '.7z', '.tar', '.gz'
        }
        
        # Directories to exclude from scanning
        self.excluded_dirs = {
            'System Volume Information', 'Windows', 'Program Files',
            'Program Files (x86)', '$Recycle.Bin', 'Recovery'
        }
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'errors': 0,
            'scan_time': 0.0
        }
    
    def should_scan_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be scanned
        """
        try:
            # Check if file exists and is readable
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Check file extension
            if file_path.suffix.lower() not in self.scan_extensions:
                return False
            
            # Check file size (skip very large files for performance)
            try:
                file_size = file_path.stat().st_size
                if file_size > 500 * 1024 * 1024:  # 500MB limit
                    return False
            except OSError:
                return False
            
            # Check if file is accessible
            try:
                with open(file_path, 'rb') as f:
                    f.read(1)  # Try to read one byte
                return True
            except (OSError, PermissionError):
                return False
                
        except Exception as e:
            self.logger.debug(f"Error checking file {file_path}: {e}")
            return False
    
    def scan_file(self, file_path: str, quarantine: bool = False) -> Dict[str, Any]:
        """
        Scan a single file for threats
        """
        start_time = time.time()
        file_path = Path(file_path)
        
        try:
            # Check if file should be scanned
            if not self.should_scan_file(file_path):
                return {
                    'status': 'skipped',
                    'file_path': str(file_path),
                    'reason': 'File not eligible for scanning',
                    'scan_time': time.time() - start_time
                }
            
            # Perform the scan
            if self.threat_engine:
                result = self.threat_engine.scan_file(str(file_path))
                
                # Handle quarantine if requested and threat found
                if quarantine and result.get('status') == 'infected':
                    try:
                        # Try to quarantine the file
                        quarantine_result = self._quarantine_file(file_path)
                        result['quarantined'] = quarantine_result
                    except Exception as e:
                        self.logger.warning(f"Failed to quarantine {file_path}: {e}")
                        result['quarantined'] = False
                
                # Update statistics
                self.stats['files_scanned'] += 1
                if result.get('status') == 'infected':
                    self.stats['threats_found'] += 1
                
                result['scan_time'] = time.time() - start_time
                self.stats['scan_time'] += result['scan_time']
                
                return result
            else:
                # No threat engine available - basic scan
                return {
                    'status': 'clean',
                    'file_path': str(file_path),
                    'message': 'No threat engine available - basic scan only',
                    'scan_time': time.time() - start_time
                }
                
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Error scanning {file_path}: {e}")
            return {
                'status': 'error',
                'file_path': str(file_path),
                'error': str(e),
                'scan_time': time.time() - start_time
            }
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      quarantine: bool = False) -> Generator[Dict[str, Any], None, None]:
        """
        Scan a directory for threats
        """
        directory_path = Path(directory_path)
        
        if not directory_path.exists() or not directory_path.is_dir():
            yield {
                'status': 'error',
                'file_path': str(directory_path),
                'error': 'Directory not found or not accessible'
            }
            return
        
        try:
            # Get files to scan
            if recursive:
                files = directory_path.rglob('*')
            else:
                files = directory_path.iterdir()
            
            for file_path in files:
                try:
                    # Skip directories and excluded directories
                    if file_path.is_dir():
                        if file_path.name in self.excluded_dirs:
                            continue
                        else:
                            continue
                    
                    # Scan the file
                    result = self.scan_file(str(file_path), quarantine)
                    yield result
                    
                except PermissionError:
                    yield {
                        'status': 'error',
                        'file_path': str(file_path),
                        'error': 'Permission denied'
                    }
                except Exception as e:
                    yield {
                        'status': 'error',
                        'file_path': str(file_path),
                        'error': str(e)
                    }
                    
        except Exception as e:
            yield {
                'status': 'error',
                'file_path': str(directory_path),
                'error': f'Directory scan failed: {e}'
            }
    
    def quick_scan(self, quarantine: bool = False) -> Dict[str, Any]:
        """
        Perform a quick scan of common locations
        """
        start_time = time.time()
        
        # Common locations to scan
        scan_locations = [
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            Path.home() / "Documents",
            Path.home() / "AppData" / "Local" / "Temp" if os.name == 'nt' else Path("/tmp")
        ]
        
        results = {
            'scan_type': 'quick',
            'start_time': start_time,
            'locations_scanned': [],
            'files_scanned': 0,
            'threats_found': 0,
            'errors': 0,
            'infected_files': [],
            'suspicious_files': [],
            'error_files': []
        }
        
        for location in scan_locations:
            if location.exists():
                results['locations_scanned'].append(str(location))
                
                for scan_result in self.scan_directory(str(location), recursive=True, quarantine=quarantine):
                    results['files_scanned'] += 1
                    
                    if scan_result['status'] == 'infected':
                        results['threats_found'] += 1
                        results['infected_files'].append(scan_result)
                    elif scan_result['status'] == 'suspicious':
                        results['suspicious_files'].append(scan_result)
                    elif scan_result['status'] == 'error':
                        results['errors'] += 1
                        results['error_files'].append(scan_result)
        
        results['scan_time'] = time.time() - start_time
        results['end_time'] = time.time()
        
        return results
    
    def _quarantine_file(self, file_path: Path) -> bool:
        """
        Quarantine a file (placeholder implementation)
        """
        try:
            # This would integrate with the quarantine manager
            # For now, just log the action
            self.logger.info(f"File {file_path} would be quarantined")
            return True
        except Exception as e:
            self.logger.error(f"Failed to quarantine {file_path}: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get scanning statistics
        """
        return self.stats.copy()
    
    def reset_statistics(self):
        """
        Reset scanning statistics
        """
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'errors': 0,
            'scan_time': 0.0
        }
