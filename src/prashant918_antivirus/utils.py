"""
Prashant918 Advanced Antivirus - Utility Functions

Common utility functions and helpers used throughout the
cybersecurity platform for various operations and tasks.
"""

import os
import sys
import platform
import subprocess
import hashlib
import json
import time
import threading
import functools
import importlib
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Package imports
from .exceptions import AntivirusError, ValidationError, ResourceError


def initialize(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Initialize the antivirus system with configuration
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Initialization status and information
    """
    try:
        init_info = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "version": get_version_info(),
            "system": get_system_info(),
            "dependencies": check_dependencies(),
            "configuration": {}
        }
        
        # Create necessary directories
        directories = [
            "data",
            "data/yara_rules",
            "logs",
            "config",
            "quarantine",
            "models",
            "signatures",
            "temp"
        ]
        
        created_dirs = []
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                created_dirs.append(directory)
                
                # Set secure permissions on Unix-like systems
                if os.name != 'nt':
                    if directory in ["logs", "config", "quarantine"]:
                        os.chmod(directory, 0o700)
                    else:
                        os.chmod(directory, 0o755)
        
        init_info["created_directories"] = created_dirs
        
        # Load configuration if provided
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.json'):
                        config_data = json.load(f)
                    else:
                        # Assume YAML
                        import yaml
                        config_data = yaml.safe_load(f)
                
                init_info["configuration"] = config_data
            except Exception as e:
                init_info["configuration_error"] = str(e)
        
        return init_info
        
    except Exception as e:
        return {
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def get_version_info() -> Dict[str, Any]:
    """Get comprehensive version information"""
    try:
        from . import __version__, __author__, __license__
        
        return {
            "version": __version__,
            "author": __author__,
            "license": __license__,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.platform(),
            "architecture": platform.architecture()[0],
            "build_date": "2024-01-01",  # This would be set during build
            "git_commit": get_git_commit_hash(),
        }
    except ImportError:
        return {
            "version": "unknown",
            "error": "Version information not available"
        }


def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    try:
        import psutil
        
        # Memory information
        memory = psutil.virtual_memory()
        
        # Disk information
        disk = psutil.disk_usage('.')
        
        # CPU information
        cpu_info = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
            "cpu_percent": psutil.cpu_percent(interval=1)
        }
        
        # Network information
        network_info = {}
        try:
            network_stats = psutil.net_io_counters()
            network_info = {
                "bytes_sent": network_stats.bytes_sent,
                "bytes_recv": network_stats.bytes_recv,
                "packets_sent": network_stats.packets_sent,
                "packets_recv": network_stats.packets_recv
            }
        except:
            network_info = {"error": "Network stats not available"}
        
        return {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "node": platform.node()
            },
            "python": {
                "version": sys.version,
                "executable": sys.executable,
                "path": sys.path[:3]  # First 3 paths only
            },
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_percent": memory.percent,
                "free_gb": round(memory.free / (1024**3), 2)
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "used_percent": round((disk.used / disk.total) * 100, 2)
            },
            "cpu": cpu_info,
            "network": network_info,
            "environment": {
                "user": os.getenv("USER") or os.getenv("USERNAME", "unknown"),
                "home": os.path.expanduser("~"),
                "cwd": os.getcwd(),
                "path_separator": os.pathsep,
                "line_separator": os.linesep
            }
        }
        
    except ImportError:
        return {
            "error": "psutil not available",
            "basic_info": {
                "platform": platform.platform(),
                "python_version": sys.version,
                "cwd": os.getcwd()
            }
        }
    except Exception as e:
        return {
            "error": f"Failed to get system info: {e}",
            "platform": platform.platform()
        }


def check_dependencies() -> Dict[str, Any]:
    """Check all dependencies and their versions"""
    dependencies = {
        "required": {
            "cryptography": ">=41.0.0",
            "requests": ">=2.31.0",
            "psutil": ">=5.9.0",
            "numpy": ">=1.24.0",
            "pandas": ">=2.0.0",
            "sqlalchemy": ">=2.0.0",
            "termcolor": ">=2.3.0",
            "pyfiglet": ">=0.8.0"
        },
        "optional": {
            "cx_Oracle": ">=8.3.0",
            "yara-python": ">=4.3.1",
            "python-magic": ">=0.4.27",
            "pefile": ">=2023.2.7",
            "tensorflow": ">=2.13.0",
            "scikit-learn": ">=1.3.0"
        },
        "platform_specific": {
            "pywin32": ">=306 (Windows only)",
            "python-prctl": ">=1.8.1 (Linux only)",
            "pyobjc": ">=9.2 (macOS only)"
        }
    }
    
    results = {
        "status": "checking",
        "required": {},
        "optional": {},
        "platform_specific": {},
        "missing_required": [],
        "missing_optional": [],
        "overall_status": True
    }
    
    # Check required dependencies
    for module, version_req in dependencies["required"].items():
        module_name = module.replace("-", "_")
        try:
            imported_module = importlib.import_module(module_name)
            version = getattr(imported_module, "__version__", "unknown")
            results["required"][module] = {
                "available": True,
                "version": version,
                "requirement": version_req
            }
        except ImportError:
            results["required"][module] = {
                "available": False,
                "version": None,
                "requirement": version_req
            }
            results["missing_required"].append(module)
            results["overall_status"] = False
    
    # Check optional dependencies
    for module, version_req in dependencies["optional"].items():
        module_name = module.replace("-", "_")
        try:
            imported_module = importlib.import_module(module_name)
            version = getattr(imported_module, "__version__", "unknown")
            results["optional"][module] = {
                "available": True,
                "version": version,
                "requirement": version_req
            }
        except ImportError:
            results["optional"][module] = {
                "available": False,
                "version": None,
                "requirement": version_req
            }
            results["missing_optional"].append(module)
    
    # Check platform-specific dependencies
    current_platform = platform.system().lower()
    for module, version_req in dependencies["platform_specific"].items():
        if ("windows" in version_req.lower() and current_platform == "windows") or \
           ("linux" in version_req.lower() and current_platform == "linux") or \
           ("macos" in version_req.lower() and current_platform == "darwin"):
            
            try:
                imported_module = importlib.import_module(module)
                version = getattr(imported_module, "__version__", "unknown")
                results["platform_specific"][module] = {
                    "available": True,
                    "version": version,
                    "requirement": version_req
                }
            except ImportError:
                results["platform_specific"][module] = {
                    "available": False,
                    "version": None,
                    "requirement": version_req
                }
    
    results["status"] = "completed"
    return results


def get_git_commit_hash() -> str:
    """Get current git commit hash if available"""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()[:8]  # Short hash
    except:
        pass
    return "unknown"


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        Hexadecimal hash string
    """
    if not os.path.isfile(file_path):
        raise ValidationError(f"File not found: {file_path}")
    
    hash_algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if algorithm not in hash_algorithms:
        raise ValidationError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_obj = hash_algorithms[algorithm]()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        raise AntivirusError(f"Failed to calculate hash for {file_path}: {e}")


def calculate_multiple_hashes(file_path: str) -> Dict[str, str]:
    """Calculate multiple hashes for a file efficiently"""
    if not os.path.isfile(file_path):
        raise ValidationError(f"File not found: {file_path}")
    
    hash_objects = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512()
    }
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
        
        return {alg: hash_obj.hexdigest() for alg, hash_obj in hash_objects.items()}
    except Exception as e:
        raise AntivirusError(f"Failed to calculate hashes for {file_path}: {e}")


def validate_file_path(file_path: str, check_exists: bool = True) -> bool:
    """
    Validate file path for security and existence
    
    Args:
        file_path: Path to validate
        check_exists: Whether to check if file exists
    
    Returns:
        True if valid, raises exception if invalid
    """
    if not file_path:
        raise ValidationError("File path cannot be empty")
    
    # Normalize path
    normalized_path = os.path.normpath(file_path)
    
    # Check for path traversal attempts
    if ".." in normalized_path:
        raise ValidationError(f"Path traversal detected in: {file_path}")
    
    # Check for absolute paths that might be suspicious
    if os.path.isabs(normalized_path):
        # Allow absolute paths but log them
        pass
    
    # Check if file exists if required
    if check_exists and not os.path.exists(normalized_path):
        raise ValidationError(f"File does not exist: {file_path}")
    
    return True


def safe_file_operation(operation: Callable, *args, **kwargs) -> Any:
    """
    Safely execute file operations with proper error handling
    
    Args:
        operation: Function to execute
        *args: Arguments for the operation
        **kwargs: Keyword arguments for the operation
    
    Returns:
        Result of the operation
    """
    try:
        return operation(*args, **kwargs)
    except PermissionError as e:
        raise AntivirusError(f"Permission denied: {e}")
    except FileNotFoundError as e:
        raise ValidationError(f"File not found: {e}")
    except OSError as e:
        raise AntivirusError(f"OS error during file operation: {e}")
    except Exception as e:
        raise AntivirusError(f"Unexpected error during file operation: {e}")


def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string"""
    if seconds < 1:
        return f"{seconds*1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.1f}s"


def retry_operation(
    operation: Callable,
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: Tuple[type, ...] = (Exception,)
) -> Callable:
    """
    Decorator for retrying operations with exponential backoff
    
    Args:
        operation: Function to retry
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts
        backoff_factor: Multiplier for delay after each attempt
        exceptions: Tuple of exceptions to catch and retry
    
    Returns:
        Decorated function
    """
    @functools.wraps(operation)
    def wrapper(*args, **kwargs):
        last_exception = None
        current_delay = delay
        
        for attempt in range(max_attempts):
            try:
                return operation(*args, **kwargs)
            except exceptions as e:
                last_exception = e
                if attempt < max_attempts - 1:
                    time.sleep(current_delay)
                    current_delay *= backoff_factor
                else:
                    break
        
        # If we get here, all attempts failed
        raise AntivirusError(
            f"Operation failed after {max_attempts} attempts",
            details={"last_exception": str(last_exception)}
        )
    
    return wrapper


def timeout_operation(timeout_seconds: float):
    """
    Decorator to add timeout to operations
    
    Args:
        timeout_seconds: Timeout in seconds
    
    Returns:
        Decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout_seconds)
            
            if thread.is_alive():
                # Force thread termination (not recommended but necessary for timeout)
                raise AntivirusError(
                    f"Operation timed out after {timeout_seconds} seconds",
                    error_code="TIMEOUT_ERROR"
                )
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
        
        return wrapper
    return decorator


def validate_config_value(value: Any, expected_type: type, constraints: Optional[Dict] = None) -> bool:
    """
    Validate configuration value against type and constraints
    
    Args:
        value: Value to validate
        expected_type: Expected type
        constraints: Additional constraints (min, max, choices, etc.)
    
    Returns:
        True if valid, raises ValidationError if invalid
    """
    # Type check
    if not isinstance(value, expected_type):
        raise ValidationError(
            f"Expected {expected_type.__name__}, got {type(value).__name__}",
            field_value=value
        )
    
    # Constraint checks
    if constraints:
        if 'min' in constraints and value < constraints['min']:
            raise ValidationError(
                f"Value {value} is below minimum {constraints['min']}",
                field_value=value
            )
        
        if 'max' in constraints and value > constraints['max']:
            raise ValidationError(
                f"Value {value} is above maximum {constraints['max']}",
                field_value=value
            )
        
        if 'choices' in constraints and value not in constraints['choices']:
            raise ValidationError(
                f"Value {value} not in allowed choices: {constraints['choices']}",
                field_value=value
            )
        
        if 'pattern' in constraints:
            import re
            if not re.match(constraints['pattern'], str(value)):
                raise ValidationError(
                    f"Value {value} does not match pattern {constraints['pattern']}",
                    field_value=value
                )
    
    return True


def create_secure_temp_file(suffix: str = "", prefix: str = "av_temp_") -> str:
    """
    Create a secure temporary file
    
    Args:
        suffix: File suffix
        prefix: File prefix
    
    Returns:
        Path to temporary file
    """
    import tempfile
    
    # Create temp directory if it doesn't exist
    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    # Set secure permissions
    if os.name != 'nt':
        os.chmod(temp_dir, 0o700)
    
    # Create temporary file
    fd, temp_path = tempfile.mkstemp(
        suffix=suffix,
        prefix=prefix,
        dir=temp_dir
    )
    
    # Close file descriptor and set secure permissions
    os.close(fd)
    if os.name != 'nt':
        os.chmod(temp_path, 0o600)
    
    return temp_path


def cleanup_temp_files(max_age_hours: int = 24) -> int:
    """
    Clean up old temporary files
    
    Args:
        max_age_hours: Maximum age of files to keep
    
    Returns:
        Number of files cleaned up
    """
    temp_dir = os.path.join(os.getcwd(), "temp")
    if not os.path.exists(temp_dir):
        return 0
    
    cutoff_time = time.time() - (max_age_hours * 3600)
    cleaned_count = 0
    
    try:
        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            if os.path.isfile(file_path):
                if os.path.getmtime(file_path) < cutoff_time:
                    try:
                        os.remove(file_path)
                        cleaned_count += 1
                    except OSError:
                        pass  # File might be in use
    except OSError:
        pass
    
    return cleaned_count


def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get comprehensive file information
    
    Args:
        file_path: Path to the file
    
    Returns:
        Dictionary with file information
    """
    if not os.path.exists(file_path):
        raise ValidationError(f"File not found: {file_path}")
    
    stat_info = os.stat(file_path)
    
    file_info = {
        "path": os.path.abspath(file_path),
        "name": os.path.basename(file_path),
        "directory": os.path.dirname(file_path),
        "size": stat_info.st_size,
        "size_formatted": format_bytes(stat_info.st_size),
        "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
        "permissions": oct(stat_info.st_mode)[-3:],
        "is_file": os.path.isfile(file_path),
        "is_directory": os.path.isdir(file_path),
        "is_symlink": os.path.islink(file_path),
    }
    
    # Add file extension and type
    if os.path.isfile(file_path):
        file_info["extension"] = os.path.splitext(file_path)[1].lower()
        
        # Try to get MIME type
        try:
            import magic
            file_info["mime_type"] = magic.from_file(file_path, mime=True)
            file_info["file_type"] = magic.from_file(file_path)
        except ImportError:
            file_info["mime_type"] = "unknown"
            file_info["file_type"] = "unknown"
    
    # Calculate hashes for files
    if os.path.isfile(file_path) and stat_info.st_size < 100 * 1024 * 1024:  # < 100MB
        try:
            file_info["hashes"] = calculate_multiple_hashes(file_path)
        except Exception as e:
            file_info["hash_error"] = str(e)
    
    return file_info


def monitor_resource_usage(func: Callable) -> Callable:
    """
    Decorator to monitor resource usage of functions
    
    Args:
        func: Function to monitor
    
    Returns:
        Decorated function with resource monitoring
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            import psutil
            process = psutil.Process()
            
            # Get initial resource usage
            start_time = time.time()
            start_memory = process.memory_info().rss
            start_cpu_times = process.cpu_times()
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Get final resource usage
            end_time = time.time()
            end_memory = process.memory_info().rss
            end_cpu_times = process.cpu_times()
            
            # Calculate usage
            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory
            cpu_time = (end_cpu_times.user - start_cpu_times.user) + \
                      (end_cpu_times.system - start_cpu_times.system)
            
            # Log resource usage
            logger = logging.getLogger(__name__)
            logger.info(
                f"Function {func.__name__} - "
                f"Time: {format_duration(execution_time)}, "
                f"Memory: {format_bytes(abs(memory_delta))}, "
                f"CPU: {cpu_time:.3f}s"
            )
            
            return result
            
        except ImportError:
            # psutil not available, just execute function
            return func(*args, **kwargs)
    
    return wrapper


def create_backup(source_path: str, backup_dir: str = "backups") -> str:
    """
    Create a backup of a file or directory
    
    Args:
        source_path: Path to backup
        backup_dir: Directory to store backups
    
    Returns:
        Path to backup file
    """
    import shutil
    
    if not os.path.exists(source_path):
        raise ValidationError(f"Source path not found: {source_path}")
    
    # Create backup directory
    os.makedirs(backup_dir, exist_ok=True)
    
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    source_name = os.path.basename(source_path)
    backup_name = f"{source_name}_{timestamp}"
    
    if os.path.isdir(source_path):
        backup_name += ".tar.gz"
        backup_path = os.path.join(backup_dir, backup_name)
        
        # Create compressed archive
        shutil.make_archive(
            backup_path.replace(".tar.gz", ""),
            "gztar",
            source_path
        )
    else:
        backup_path = os.path.join(backup_dir, backup_name)
        shutil.copy2(source_path, backup_path)
    
    return backup_path


def verify_integrity(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify file integrity using hash comparison
    
    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm to use
    
    Returns:
        True if integrity verified, False otherwise
    """
    try:
        actual_hash = calculate_file_hash(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext
    
    # Ensure it's not empty
    if not sanitized or sanitized.isspace():
        sanitized = "unnamed_file"
    
    return sanitized


def is_safe_path(path: str, base_path: str = ".") -> bool:
    """
    Check if a path is safe (no directory traversal)
    
    Args:
        path: Path to check
        base_path: Base path to restrict to
    
    Returns:
        True if path is safe, False otherwise
    """
    try:
        # Resolve both paths
        resolved_path = os.path.realpath(path)
        resolved_base = os.path.realpath(base_path)
        
        # Check if resolved path starts with base path
        return resolved_path.startswith(resolved_base)
    except Exception:
        return False


# Performance monitoring utilities
class PerformanceTimer:
    """Context manager for timing operations"""
    
    def __init__(self, operation_name: str = "Operation"):
        self.operation_name = operation_name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        
        logger = logging.getLogger(__name__)
        logger.info(f"{self.operation_name} completed in {format_duration(duration)}")
    
    @property
    def duration(self) -> Optional[float]:
        """Get operation duration in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


class ResourceMonitor:
    """Monitor system resource usage"""
    
    def __init__(self):
        self.start_stats = None
        self.end_stats = None
    
    def start(self):
        """Start monitoring"""
        try:
            import psutil
            self.start_stats = {
                "memory": psutil.virtual_memory(),
                "cpu_percent": psutil.cpu_percent(),
                "disk_io": psutil.disk_io_counters(),
                "network_io": psutil.net_io_counters(),
                "timestamp": time.time()
            }
        except ImportError:
            self.start_stats = {"timestamp": time.time()}
    
    def stop(self) -> Dict[str, Any]:
        """Stop monitoring and return statistics"""
        try:
            import psutil
            self.end_stats = {
                "memory": psutil.virtual_memory(),
                "cpu_percent": psutil.cpu_percent(),
                "disk_io": psutil.disk_io_counters(),
                "network_io": psutil.net_io_counters(),
                "timestamp": time.time()
            }
            
            if self.start_stats:
                return self._calculate_deltas()
            else:
                return self.end_stats
                
        except ImportError:
            return {"error": "psutil not available"}
    
    def _calculate_deltas(self) -> Dict[str, Any]:
        """Calculate resource usage deltas"""
        duration = self.end_stats["timestamp"] - self.start_stats["timestamp"]
        
        deltas = {
            "duration": duration,
            "memory_change": self.end_stats["memory"].used - self.start_stats["memory"].used,
            "cpu_average": (self.start_stats["cpu_percent"] + self.end_stats["cpu_percent"]) / 2
        }
        
        # Calculate I/O deltas if available
        if self.start_stats.get("disk_io") and self.end_stats.get("disk_io"):
            deltas["disk_read"] = self.end_stats["disk_io"].read_bytes - self.start_stats["disk_io"].read_bytes
            deltas["disk_write"] = self.end_stats["disk_io"].write_bytes - self.start_stats["disk_io"].write_bytes
        
        if self.start_stats.get("network_io") and self.end_stats.get("network_io"):
            deltas["network_sent"] = self.end_stats["network_io"].bytes_sent - self.start_stats["network_io"].bytes_sent
            deltas["network_recv"] = self.end_stats["network_io"].bytes_recv - self.start_stats["network_io"].bytes_recv
        
        return deltas


# Export all utility functions
__all__ = [
    "initialize",
    "get_version_info", 
    "get_system_info",
    "check_dependencies",
    "calculate_file_hash",
    "calculate_multiple_hashes",
    "validate_file_path",
    "safe_file_operation",
    "format_bytes",
    "format_duration",
    "retry_operation",
    "timeout_operation",
    "validate_config_value",
    "create_secure_temp_file",
    "cleanup_temp_files",
    "get_file_info",
    "monitor_resource_usage",
    "create_backup",
    "verify_integrity",
    "sanitize_filename",
    "is_safe_path",
    "PerformanceTimer",
    "ResourceMonitor"
]