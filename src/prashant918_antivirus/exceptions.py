"""
Custom Exception Classes - Comprehensive error handling for the antivirus system
"""
import traceback
from typing import Dict, Any, Optional
from datetime import datetime

class AntivirusError(Exception):
    """Base exception class for all antivirus-related errors"""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.cause = cause
        self.timestamp = datetime.now()
        self.traceback = traceback.format_exc()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/serialization"""
        return {
            'error_type': self.__class__.__name__,
            'error_code': self.error_code,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'traceback': self.traceback,
            'cause': str(self.cause) if self.cause else None
        }
    
    def __str__(self) -> str:
        details_str = f" - Details: {self.details}" if self.details else ""
        return f"[{self.error_code}] {self.message}{details_str}"

# Configuration Errors
class ConfigurationError(AntivirusError):
    """Configuration-related errors"""
    
    def __init__(self, message: str, config_key: Optional[str] = None, 
                 config_value: Optional[Any] = None, **kwargs):
        details = kwargs.get('details', {})
        if config_key:
            details['config_key'] = config_key
        if config_value is not None:
            details['config_value'] = config_value
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Database Errors
class DatabaseError(AntivirusError):
    """Database operation errors"""
    
    def __init__(self, message: str, query: Optional[str] = None, 
                 connection_info: Optional[Dict] = None, **kwargs):
        details = kwargs.get('details', {})
        if query:
            details['query'] = query
        if connection_info:
            details['connection_info'] = connection_info
        kwargs['details'] = details
        super().__init__(message, **kwargs)

class ConnectionError(DatabaseError):
    """Database connection errors"""
    pass

class QueryError(DatabaseError):
    """Database query errors"""
    pass

# Scanning Errors
class ScanError(AntivirusError):
    """File scanning errors"""
    
    def __init__(self, message: str, file_path: Optional[str] = None, 
                 scan_type: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if file_path:
            details['file_path'] = file_path
        if scan_type:
            details['scan_type'] = scan_type
        kwargs['details'] = details
        super().__init__(message, **kwargs)

class FileAccessError(ScanError):
    """File access errors during scanning"""
    pass

class MalwareDetectedError(ScanError):
    """Malware detection error"""
    
    def __init__(self, message: str, threat_name: Optional[str] = None,
                 threat_type: Optional[str] = None, confidence: Optional[float] = None, **kwargs):
        details = kwargs.get('details', {})
        if threat_name:
            details['threat_name'] = threat_name
        if threat_type:
            details['threat_type'] = threat_type
        if confidence is not None:
            details['confidence'] = confidence
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Quarantine Errors
class QuarantineError(AntivirusError):
    """Quarantine operation errors"""
    
    def __init__(self, message: str, file_path: Optional[str] = None,
                 quarantine_path: Optional[str] = None, operation: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if file_path:
            details['file_path'] = file_path
        if quarantine_path:
            details['quarantine_path'] = quarantine_path
        if operation:
            details['operation'] = operation
        kwargs['details'] = details
        super().__init__(message, **kwargs)

class QuarantineAccessError(QuarantineError):
    """Quarantine access errors"""
    pass

# Encryption Errors
class EncryptionError(AntivirusError):
    """Encryption/decryption errors"""
    
    def __init__(self, message: str, operation: Optional[str] = None,
                 algorithm: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if operation:
            details['operation'] = operation
        if algorithm:
            details['algorithm'] = algorithm
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Signature Errors
class SignatureError(AntivirusError):
    """Signature-related errors"""
    
    def __init__(self, message: str, signature_type: Optional[str] = None,
                 signature_source: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if signature_type:
            details['signature_type'] = signature_type
        if signature_source:
            details['signature_source'] = signature_source
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Update Errors
class UpdateError(AntivirusError):
    """Update-related errors"""
    
    def __init__(self, message: str, update_source: Optional[str] = None,
                 update_type: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if update_source:
            details['update_source'] = update_source
        if update_type:
            details['update_type'] = update_type
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Network Errors
class NetworkError(AntivirusError):
    """Network-related errors"""
    
    def __init__(self, message: str, url: Optional[str] = None,
                 status_code: Optional[int] = None, **kwargs):
        details = kwargs.get('details', {})
        if url:
            details['url'] = url
        if status_code:
            details['status_code'] = status_code
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Authentication/Authorization Errors
class AuthenticationError(AntivirusError):
    """Authentication errors"""
    
    def __init__(self, message: str, auth_method: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if auth_method:
            details['auth_method'] = auth_method
        kwargs['details'] = details
        super().__init__(message, **kwargs)

class AuthorizationError(AntivirusError):
    """Authorization errors"""
    
    def __init__(self, message: str, required_permission: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if required_permission:
            details['required_permission'] = required_permission
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Validation Errors
class ValidationError(AntivirusError):
    """Data validation errors"""
    
    def __init__(self, message: str, field_name: Optional[str] = None,
                 field_value: Optional[Any] = None, validation_rules: Optional[Dict] = None, **kwargs):
        details = kwargs.get('details', {})
        if field_name:
            details['field_name'] = field_name
        if field_value is not None:
            details['field_value'] = field_value
        if validation_rules:
            details['validation_rules'] = validation_rules
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Resource Errors
class ResourceError(AntivirusError):
    """Resource-related errors (memory, disk, etc.)"""
    
    def __init__(self, message: str, resource_type: Optional[str] = None,
                 resource_limit: Optional[Any] = None, current_usage: Optional[Any] = None, **kwargs):
        details = kwargs.get('details', {})
        if resource_type:
            details['resource_type'] = resource_type
        if resource_limit is not None:
            details['resource_limit'] = resource_limit
        if current_usage is not None:
            details['current_usage'] = current_usage
        kwargs['details'] = details
        super().__init__(message, **kwargs)

class MemoryError(ResourceError):
    """Memory-related errors"""
    pass

class DiskSpaceError(ResourceError):
    """Disk space errors"""
    pass

# Timeout Errors
class TimeoutError(AntivirusError):
    """Timeout errors"""
    
    def __init__(self, message: str, timeout_duration: Optional[float] = None,
                 operation: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if timeout_duration is not None:
            details['timeout_duration'] = timeout_duration
        if operation:
            details['operation'] = operation
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Service Errors
class ServiceError(AntivirusError):
    """Service management errors"""
    
    def __init__(self, message: str, service_name: Optional[str] = None,
                 operation: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if service_name:
            details['service_name'] = service_name
        if operation:
            details['operation'] = operation
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Critical System Errors
class CriticalError(AntivirusError):
    """Critical system errors that require immediate attention"""
    
    def __init__(self, message: str, system_component: Optional[str] = None,
                 recovery_action: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if system_component:
            details['system_component'] = system_component
        if recovery_action:
            details['recovery_action'] = recovery_action
        kwargs['details'] = details
        super().__init__(message, **kwargs)

# Utility Functions
def handle_exception(exception: Exception, logger=None, context: Optional[Dict] = None, 
                    reraise_as: Optional[type] = None) -> Optional[AntivirusError]:
    """
    Handle exceptions with logging and optional re-raising
    """
    if isinstance(exception, AntivirusError):
        antivirus_error = exception
    else:
        antivirus_error = AntivirusError(
            message=str(exception),
            cause=exception,
            details=context or {}
        )
    
    if logger:
        logger.error(f"Exception handled: {antivirus_error}", extra=antivirus_error.to_dict())
    
    if reraise_as:
        if issubclass(reraise_as, AntivirusError):
            raise reraise_as(
                message=antivirus_error.message,
                details=antivirus_error.details,
                cause=antivirus_error.cause
            )
        else:
            raise reraise_as(str(antivirus_error))
    
    return antivirus_error

def create_error_response(exception: Exception, include_traceback: bool = False) -> Dict[str, Any]:
    """
    Create standardized error response for APIs
    """
    if isinstance(exception, AntivirusError):
        response = exception.to_dict()
    else:
        response = {
            'error_type': exception.__class__.__name__,
            'error_code': 'UNKNOWN_ERROR',
            'message': str(exception),
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'traceback': traceback.format_exc() if include_traceback else None,
            'cause': None
        }
    
    if not include_traceback:
        response.pop('traceback', None)
    
    return response

# Error code registry for programmatic access
ERROR_CODE_REGISTRY = {
    'CONFIGURATION_ERROR': ConfigurationError,
    'DATABASE_ERROR': DatabaseError,
    'CONNECTION_ERROR': ConnectionError,
    'QUERY_ERROR': QueryError,
    'SCAN_ERROR': ScanError,
    'FILE_ACCESS_ERROR': FileAccessError,
    'MALWARE_DETECTED_ERROR': MalwareDetectedError,
    'QUARANTINE_ERROR': QuarantineError,
    'QUARANTINE_ACCESS_ERROR': QuarantineAccessError,
    'ENCRYPTION_ERROR': EncryptionError,
    'SIGNATURE_ERROR': SignatureError,
    'UPDATE_ERROR': UpdateError,
    'NETWORK_ERROR': NetworkError,
    'AUTHENTICATION_ERROR': AuthenticationError,
    'AUTHORIZATION_ERROR': AuthorizationError,
    'VALIDATION_ERROR': ValidationError,
    'RESOURCE_ERROR': ResourceError,
    'MEMORY_ERROR': MemoryError,
    'DISK_SPACE_ERROR': DiskSpaceError,
    'TIMEOUT_ERROR': TimeoutError,
    'SERVICE_ERROR': ServiceError,
    'CRITICAL_ERROR': CriticalError
}

def get_exception_class(error_code: str) -> Optional[type]:
    """Get exception class by error code"""
    return ERROR_CODE_REGISTRY.get(error_code.upper())

def create_exception_from_code(error_code: str, message: str, **kwargs) -> AntivirusError:
    """Create exception instance from error code"""
    exception_class = get_exception_class(error_code)
    if exception_class:
        return exception_class(message, **kwargs)
    else:
        return AntivirusError(message, error_code=error_code, **kwargs)