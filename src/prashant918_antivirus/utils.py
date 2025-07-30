"""
Prashant918 Advanced Antivirus - Enhanced Utility Functions
Cross-platform utility functions with comprehensive system support
"""

import os
import sys
import hashlib
import tempfile
import shutil
import platform
import subprocess
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime

# Core imports with error handling
try:
    from .logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from .config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

# Optional imports
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

# Platform detection
PLATFORM = platform.system().lower()
ARCHITECTURE = platform.machine().lower()

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    try:
        info = {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'architecture': platform.architecture(),
                'python_version': platform.python_version(),
                'python_implementation': platform.python_implementation()
            },
            'paths': {
                'home': str(Path.home()),
                'temp': tempfile.gettempdir(),
                'cwd': os.getcwd()
            },
            'environment': {
                'user': os.environ.get('USER') or os.environ.get('USERNAME', 'Unknown'),
                'path_separator': os.pathsep,
                'line_separator': os.linesep
            }
        }
        
        # Add memory and disk info if psutil is available
        if HAS_PSUTIL:
            try:
                memory = psutil.virtual_memory()
                info['memory'] = {
                    'total_gb': memory.total / (1024**3),
                    'available_gb': memory.available / (1024**3),
                    'used_gb': memory.used / (1024**3),
                    'used_percent': memory.percent
                }
                
                disk = psutil.disk_usage('/')
                info['disk'] = {
                    'total_gb': disk.total / (1024**3),
                    'free_gb': disk.free / (1024**3),
                    'used_gb': disk.used / (1024**3),
                    'used_percent': (disk.used / disk.total) * 100
                }
                
                info['cpu'] = {
                    'count': psutil.cpu_count(),
                    'count_logical': psutil.cpu_count(logical=True),
                    'percent': psutil.cpu_percent(interval=1)
                }
                
            except Exception as e:
                logger = SecureLogger("SystemInfo")
                logger.debug(f"Error getting system stats: {e}")
        
        return info
        
    except Exception as e:
        logger = SecureLogger("SystemInfo")
        logger.error(f"Error getting system info: {e}")
        return {'error': str(e)}

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate file hash with multiple algorithm support"""
    try:
        hash_obj = hashlib.new(algorithm.lower())
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
        
    except Exception as e:
        logger = SecureLogger("FileHash")
        logger.error(f"Error calculating {algorithm} hash for {file_path}: {e}")
        return None

def calculate_multiple_hashes(file_path: str) -> Dict[str, Optional[str]]:
    """Calculate multiple hashes for a file"""
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    hashes = {}
    
    try:
        hash_objects = {alg: hashlib.new(alg) for alg in algorithms}
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
        
        for alg, hash_obj in hash_objects.items():
            hashes[alg] = hash_obj.hexdigest()
            
    except Exception as e:
        logger = SecureLogger("MultiHash")
        logger.error(f"Error calculating hashes for {file_path}: {e}")
        for alg in algorithms:
            hashes[alg] = None
    
    return hashes

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for cross-platform compatibility"""
    try:
        # Remove or replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove control characters
        filename = ''.join(char for char in filename if ord(char) >= 32)
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
        
        # Handle reserved names on Windows
        if PLATFORM == 'windows':
            reserved_names = {
                'CON', 'PRN', 'AUX', 'NUL',
                'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
            }
            
            name_without_ext = os.path.splitext(filename)[0].upper()
            if name_without_ext in reserved_names:
                filename = f"_{filename}"
        
        return filename
        
    except Exception as e:
        logger = SecureLogger("FileSanitize")
        logger.error(f"Error sanitizing filename {filename}: {e}")
        return f"sanitized_{int(time.time())}"

def create_secure_temp_file(suffix: str = '', prefix: str = 'antivirus_', 
                           directory: Optional[str] = None) -> str:
    """Create a secure temporary file"""
    try:
        fd, temp_path = tempfile.mkstemp(
            suffix=suffix,
            prefix=prefix,
            dir=directory
        )
        
        # Close the file descriptor but keep the file
        os.close(fd)
        
        # Set secure permissions
        if hasattr(os, 'chmod'):
            os.chmod(temp_path, 0o600)
        
        return temp_path
        
    except Exception as e:
        logger = SecureLogger("TempFile")
        logger.error(f"Error creating secure temp file: {e}")
        raise

def create_secure_temp_dir(suffix: str = '', prefix: str = 'antivirus_',
                          directory: Optional[str] = None) -> str:
    """Create a secure temporary directory"""
    try:
        temp_dir = tempfile.mkdtemp(
            suffix=suffix,
            prefix=prefix,
            dir=directory
        )
        
        # Set secure permissions
        if hasattr(os, 'chmod'):
            os.chmod(temp_dir, 0o700)
        
        return temp_dir
        
    except Exception as e:
        logger = SecureLogger("TempDir")
        logger.error(f"Error creating secure temp directory: {e}")
        raise

def safe_file_operation(operation: str, source: str, destination: str = None) -> bool:
    """Perform safe file operations with error handling"""
    try:
        source_path = Path(source)
        
        if operation == 'copy':
            if not destination:
                raise ValueError("Destination required for copy operation")
            shutil.copy2(source, destination)
            
        elif operation == 'move':
            if not destination:
                raise ValueError("Destination required for move operation")
            shutil.move(source, destination)
            
        elif operation == 'delete':
            if source_path.is_file():
                source_path.unlink()
            elif source_path.is_dir():
                shutil.rmtree(source)
            
        elif operation == 'backup':
            if not destination:
                destination = f"{source}.backup_{int(time.time())}"
            shutil.copy2(source, destination)
            
        else:
            raise ValueError(f"Unknown operation: {operation}")
        
        return True
        
    except Exception as e:
        logger = SecureLogger("FileOp")
        logger.error(f"Error in {operation} operation from {source} to {destination}: {e}")
        return False

def get_file_info(file_path: str) -> Dict[str, Any]:
    """Get comprehensive file information"""
    try:
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {'error': 'File not found'}
        
        stat_info = file_path.stat()
        
        info = {
            'path': str(file_path.absolute()),
            'name': file_path.name,
            'stem': file_path.stem,
            'suffix': file_path.suffix,
            'size': stat_info.st_size,
            'size_human': format_file_size(stat_info.st_size),
            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            'permissions': oct(stat_info.st_mode)[-3:],
            'is_file': file_path.is_file(),
            'is_dir': file_path.is_dir(),
            'is_symlink': file_path.is_symlink()
        }
        
        # Add file type detection if magic is available
        if HAS_MAGIC and file_path.is_file():
            try:
                info['mime_type'] = magic.from_file(str(file_path), mime=True)
                info['file_type'] = magic.from_file(str(file_path))
            except Exception as e:
                logger = SecureLogger("FileInfo")
                logger.debug(f"Magic detection failed: {e}")
        
        # Add hash information
        if file_path.is_file() and stat_info.st_size < 100 * 1024 * 1024:  # < 100MB
            info['hashes'] = calculate_multiple_hashes(str(file_path))
        
        return info
        
    except Exception as e:
        logger = SecureLogger("FileInfo")
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {'error': str(e)}

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    try:
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
        
    except Exception:
        return f"{size_bytes} B"

def validate_file_path(file_path: str, check_exists: bool = True, 
                      check_readable: bool = True) -> Tuple[bool, str]:
    """Validate file path with comprehensive checks"""
    try:
        path = Path(file_path)
        
        # Check for path traversal
        try:
            path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            # Path is outside current directory, check if it's absolute and safe
            if not path.is_absolute():
                return False, "Relative path traversal detected"
        
        # Check if path exists
        if check_exists and not path.exists():
            return False, "Path does not exist"
        
        # Check if readable
        if check_readable and path.exists():
            if not os.access(path, os.R_OK):
                return False, "Path is not readable"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\.\.[\\/]',  # Path traversal
            r'[<>:"|?*]',  # Invalid characters
            r'^\s*$',      # Empty or whitespace only
        ]
        
        path_str = str(path)
        for pattern in suspicious_patterns:
            if re.search(pattern, path_str):
                return False, f"Suspicious pattern detected: {pattern}"
        
        return True, "Valid path"
        
    except Exception as e:
        return False, f"Path validation error: {e}"

def run_command(command: List[str], timeout: int = 30, 
               capture_output: bool = True) -> Dict[str, Any]:
    """Run system command safely with timeout"""
    try:
        logger = SecureLogger("Command")
        logger.info(f"Running command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            check=False
        )
        
        return {
            'returncode': result.returncode,
            'stdout': result.stdout if capture_output else '',
            'stderr': result.stderr if capture_output else '',
            'success': result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': f'Command timed out after {timeout} seconds',
            'success': False
        }
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': str(e),
            'success': False
        }

def check_admin_privileges() -> bool:
    """Check if running with administrator/root privileges"""
    try:
        if PLATFORM == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def ensure_directory_exists(directory: str, mode: int = 0o755) -> bool:
    """Ensure directory exists with proper permissions"""
    try:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        
        # Set permissions on Unix-like systems
        if hasattr(os, 'chmod') and PLATFORM != 'windows':
            os.chmod(path, mode)
        
        return True
        
    except Exception as e:
        logger = SecureLogger("DirCreate")
        logger.error(f"Error creating directory {directory}: {e}")
        return False

def cleanup_temp_files(pattern: str = 'antivirus_*', max_age_hours: int = 24) -> int:
    """Clean up old temporary files"""
    try:
        temp_dir = Path(tempfile.gettempdir())
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        cleaned_count = 0
        
        for temp_file in temp_dir.glob(pattern):
            try:
                file_age = current_time - temp_file.stat().st_mtime
                if file_age > max_age_seconds:
                    if temp_file.is_file():
                        temp_file.unlink()
                    elif temp_file.is_dir():
                        shutil.rmtree(temp_file)
                    cleaned_count += 1
            except Exception as e:
                logger = SecureLogger("TempCleanup")
                logger.debug(f"Error cleaning temp file {temp_file}: {e}")
        
        return cleaned_count
        
    except Exception as e:
        logger = SecureLogger("TempCleanup")
        logger.error(f"Error during temp cleanup: {e}")
        return 0

def get_available_disk_space(path: str = '.') -> Dict[str, int]:
    """Get available disk space information"""
    try:
        if HAS_PSUTIL:
            usage = psutil.disk_usage(path)
            return {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': (usage.used / usage.total) * 100
            }
        else:
            # Fallback using shutil
            total, used, free = shutil.disk_usage(path)
            return {
                'total': total,
                'used': used,
                'free': free,
                'percent': (used / total) * 100
            }
    except Exception as e:
        logger = SecureLogger("DiskSpace")
        logger.error(f"Error getting disk space for {path}: {e}")
        return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}

def is_network_available() -> bool:
    """Check if network connectivity is available"""
    try:
        import socket
        
        # Try to connect to a reliable DNS server
        with socket.create_connection(("8.8.8.8", 53), timeout=3):
            return True
    except Exception:
        return False

def get_process_info(pid: Optional[int] = None) -> Dict[str, Any]:
    """Get process information"""
    try:
        if not HAS_PSUTIL:
            return {'error': 'psutil not available'}
        
        if pid is None:
            pid = os.getpid()
        
        process = psutil.Process(pid)
        
        return {
            'pid': process.pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'status': process.status(),
            'create_time': process.create_time(),
            'cpu_percent': process.cpu_percent(),
            'memory_info': process.memory_info()._asdict(),
            'num_threads': process.num_threads(),
            'username': process.username()
        }
        
    except Exception as e:
        logger = SecureLogger("ProcessInfo")
        logger.error(f"Error getting process info for PID {pid}: {e}")
        return {'error': str(e)}

def generate_unique_id(prefix: str = '', length: int = 16) -> str:
    """Generate a unique identifier"""
    try:
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        unique_part = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        if prefix:
            return f"{prefix}_{unique_part}"
        return unique_part
        
    except Exception:
        # Fallback to timestamp-based ID
        import random
        timestamp = str(int(time.time()))
        random_part = str(random.randint(1000, 9999))
        
        if prefix:
            return f"{prefix}_{timestamp}_{random_part}"
        return f"{timestamp}_{random_part}"

def validate_json_data(data: str) -> Tuple[bool, Union[Dict, List, str]]:
    """Validate and parse JSON data"""
    try:
        parsed_data = json.loads(data)
        return True, parsed_data
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    except Exception as e:
        return False, f"JSON validation error: {e}"

def safe_json_dump(data: Any, file_path: str, indent: int = 2) -> bool:
    """Safely dump data to JSON file"""
    try:
        temp_file = create_secure_temp_file(suffix='.json')
        
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=indent, default=str)
        
        # Atomic move to final location
        shutil.move(temp_file, file_path)
        return True
        
    except Exception as e:
        logger = SecureLogger("JSONDump")
        logger.error(f"Error dumping JSON to {file_path}: {e}")
        return False

def benchmark_function(func, *args, **kwargs) -> Dict[str, Any]:
    """Benchmark function execution time"""
    try:
        start_time = time.perf_counter()
        start_memory = 0
        
        if HAS_PSUTIL:
            process = psutil.Process()
            start_memory = process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        end_time = time.perf_counter()
        end_memory = 0
        
        if HAS_PSUTIL:
            end_memory = process.memory_info().rss
        
        return {
            'result': result,
            'execution_time': end_time - start_time,
            'memory_delta': end_memory - start_memory if HAS_PSUTIL else 0,
            'success': True
        }
        
    except Exception as e:
        return {
            'result': None,
            'execution_time': 0,
            'memory_delta': 0,
            'success': False,
            'error': str(e)
        }

# Utility constants
COMMON_EXECUTABLE_EXTENSIONS = {
    '.exe', '.com', '.scr', '.bat', '.cmd', '.pif', '.app', '.deb', 
    '.rpm', '.dmg', '.pkg', '.msi', '.jar', '.vbs', '.js', '.ps1'
}

COMMON_ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', 
    '.iso', '.img', '.dmg'
}

COMMON_DOCUMENT_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
    '.odt', '.ods', '.odp', '.rtf', '.txt'
}

def get_file_category(file_path: str) -> str:
    """Categorize file based on extension"""
    try:
        extension = Path(file_path).suffix.lower()
        
        if extension in COMMON_EXECUTABLE_EXTENSIONS:
            return 'executable'
        elif extension in COMMON_ARCHIVE_EXTENSIONS:
            return 'archive'
        elif extension in COMMON_DOCUMENT_EXTENSIONS:
            return 'document'
        elif extension.startswith('.'):
            return 'other'
        else:
            return 'unknown'
            
    except Exception:
        return 'unknown'

# Export all utility functions
__all__ = [
    'get_system_info', 'calculate_file_hash', 'calculate_multiple_hashes',
    'sanitize_filename', 'create_secure_temp_file', 'create_secure_temp_dir',
    'safe_file_operation', 'get_file_info', 'format_file_size',
    'validate_file_path', 'run_command', 'check_admin_privileges',
    'ensure_directory_exists', 'cleanup_temp_files', 'get_available_disk_space',
    'is_network_available', 'get_process_info', 'generate_unique_id',
    'validate_json_data', 'safe_json_dump', 'benchmark_function',
    'get_file_category', 'COMMON_EXECUTABLE_EXTENSIONS', 'COMMON_ARCHIVE_EXTENSIONS',
    'COMMON_DOCUMENT_EXTENSIONS'
]