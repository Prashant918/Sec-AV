"""
Prashant918 Advanced Antivirus - Exception Classes

Custom exception hierarchy for comprehensive error handling
and debugging throughout the cybersecurity platform.
"""

from typing import Optional, Dict, Any, List
import traceback
import sys
from datetime import datetime


class AntivirusError(Exception):
    """Base exception class for all antivirus-related errors"""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.cause = cause
        self.timestamp = datetime.now()
        self.traceback_info = traceback.format_exc() if sys.exc_info()[0] else None

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/serialization"""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "traceback": self.traceback_info,
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        base_msg = f"[{self.error_code}] {self.message}"
        if self.details:
            base_msg += f" | Details: {self.details}"
        return base_msg


class ConfigurationError(AntivirusError):
    """Raised when configuration-related errors occur"""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if config_key:
            details["config_key"] = config_key
        if config_value is not None:
            details["config_value"] = str(config_value)

        super().__init__(message, error_code="CONFIG_ERROR", details=details, **kwargs)


class DatabaseError(AntivirusError):
    """Raised when database-related errors occur"""

    def __init__(
        self,
        message: str,
        query: Optional[str] = None,
        connection_info: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if query:
            details["query"] = query
        if connection_info:
            details["connection_info"] = connection_info

        super().__init__(message, error_code="DB_ERROR", details=details, **kwargs)


class ConnectionError(DatabaseError):
    """Raised when database connection errors occur"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, error_code="DB_CONNECTION_ERROR", **kwargs)


class QueryError(DatabaseError):
    """Raised when database query errors occur"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, error_code="DB_QUERY_ERROR", **kwargs)


class ScanError(AntivirusError):
    """Raised when file scanning errors occur"""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        scan_type: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if file_path:
            details["file_path"] = file_path
        if scan_type:
            details["scan_type"] = scan_type

        super().__init__(message, error_code="SCAN_ERROR", details=details, **kwargs)


class FileAccessError(ScanError):
    """Raised when file access errors occur during scanning"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, error_code="FILE_ACCESS_ERROR", **kwargs)


class MalwareDetectedError(ScanError):
    """Raised when malware is detected during scanning"""

    def __init__(
        self,
        message: str,
        threat_name: Optional[str] = None,
        threat_type: Optional[str] = None,
        confidence: Optional[float] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if threat_name:
            details["threat_name"] = threat_name
        if threat_type:
            details["threat_type"] = threat_type
        if confidence is not None:
            details["confidence"] = confidence

        super().__init__(
            message, error_code="MALWARE_DETECTED", details=details, **kwargs
        )


class QuarantineError(AntivirusError):
    """Raised when quarantine-related errors occur"""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        quarantine_path: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if file_path:
            details["file_path"] = file_path
        if quarantine_path:
            details["quarantine_path"] = quarantine_path
        if operation:
            details["operation"] = operation

        super().__init__(
            message, error_code="QUARANTINE_ERROR", details=details, **kwargs
        )


class QuarantineAccessError(QuarantineError):
    """Raised when quarantine access errors occur"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, error_code="QUARANTINE_ACCESS_ERROR", **kwargs)


class EncryptionError(AntivirusError):
    """Raised when encryption/decryption errors occur"""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        algorithm: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if operation:
            details["operation"] = operation
        if algorithm:
            details["algorithm"] = algorithm

        super().__init__(
            message, error_code="ENCRYPTION_ERROR", details=details, **kwargs
        )


class SignatureError(AntivirusError):
    """Raised when signature-related errors occur"""

    def __init__(
        self,
        message: str,
        signature_type: Optional[str] = None,
        signature_source: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if signature_type:
            details["signature_type"] = signature_type
        if signature_source:
            details["signature_source"] = signature_source

        super().__init__(
            message, error_code="SIGNATURE_ERROR", details=details, **kwargs
        )


class UpdateError(AntivirusError):
    """Raised when update-related errors occur"""

    def __init__(
        self,
        message: str,
        update_source: Optional[str] = None,
        update_type: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if update_source:
            details["update_source"] = update_source
        if update_type:
            details["update_type"] = update_type

        super().__init__(message, error_code="UPDATE_ERROR", details=details, **kwargs)


class NetworkError(AntivirusError):
    """Raised when network-related errors occur"""

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if url:
            details["url"] = url
        if status_code:
            details["status_code"] = status_code

        super().__init__(message, error_code="NETWORK_ERROR", details=details, **kwargs)


class AuthenticationError(AntivirusError):
    """Raised when authentication errors occur"""

    def __init__(self, message: str, auth_method: Optional[str] = None, **kwargs):
        details = kwargs.get("details", {})
        if auth_method:
            details["auth_method"] = auth_method

        super().__init__(message, error_code="AUTH_ERROR", details=details, **kwargs)


class AuthorizationError(AntivirusError):
    """Raised when authorization errors occur"""

    def __init__(
        self, message: str, required_permission: Optional[str] = None, **kwargs
    ):
        details = kwargs.get("details", {})
        if required_permission:
            details["required_permission"] = required_permission

        super().__init__(message, error_code="AUTHZ_ERROR", details=details, **kwargs)


class ValidationError(AntivirusError):
    """Raised when validation errors occur"""

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[Any] = None,
        validation_rules: Optional[List[str]] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if field_name:
            details["field_name"] = field_name
        if field_value is not None:
            details["field_value"] = str(field_value)
        if validation_rules:
            details["validation_rules"] = validation_rules

        super().__init__(
            message, error_code="VALIDATION_ERROR", details=details, **kwargs
        )


class ResourceError(AntivirusError):
    """Raised when resource-related errors occur"""

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_limit: Optional[Any] = None,
        current_usage: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        if resource_limit is not None:
            details["resource_limit"] = str(resource_limit)
        if current_usage is not None:
            details["current_usage"] = str(current_usage)

        super().__init__(
            message, error_code="RESOURCE_ERROR", details=details, **kwargs
        )


class MemoryError(ResourceError):
    """Raised when memory-related errors occur"""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, resource_type="memory", error_code="MEMORY_ERROR", **kwargs
        )


class DiskSpaceError(ResourceError):
    """Raised when disk space errors occur"""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, resource_type="disk_space", error_code="DISK_SPACE_ERROR", **kwargs
        )


class TimeoutError(AntivirusError):
    """Raised when timeout errors occur"""

    def __init__(
        self,
        message: str,
        timeout_duration: Optional[float] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if timeout_duration is not None:
            details["timeout_duration"] = timeout_duration
        if operation:
            details["operation"] = operation

        super().__init__(message, error_code="TIMEOUT_ERROR", details=details, **kwargs)


class CriticalError(AntivirusError):
    """Raised for critical system errors that require immediate attention"""

    def __init__(
        self,
        message: str,
        system_component: Optional[str] = None,
        recovery_action: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.get("details", {})
        if system_component:
            details["system_component"] = system_component
        if recovery_action:
            details["recovery_action"] = recovery_action

        super().__init__(
            message, error_code="CRITICAL_ERROR", details=details, **kwargs
        )


# Exception handler utility functions
def handle_exception(
    exception: Exception,
    logger=None,
    reraise: bool = True,
    context: Optional[Dict[str, Any]] = None,
) -> Optional[AntivirusError]:
    """
    Handle exceptions with proper logging and conversion to AntivirusError

    Args:
        exception: The exception to handle
        logger: Logger instance for error logging
        reraise: Whether to reraise the exception
        context: Additional context information

    Returns:
        AntivirusError instance if not reraising
    """
    # Convert to AntivirusError if not already
    if not isinstance(exception, AntivirusError):
        av_error = AntivirusError(
            message=str(exception), details=context or {}, cause=exception
        )
    else:
        av_error = exception
        if context:
            av_error.details.update(context)

    # Log the error
    if logger:
        error_dict = av_error.to_dict()
        logger.error(f"Exception handled: {error_dict}")

    if reraise:
        raise av_error

    return av_error


def create_error_response(
    error: AntivirusError, include_traceback: bool = False
) -> Dict[str, Any]:
    """
    Create a standardized error response dictionary

    Args:
        error: The AntivirusError instance
        include_traceback: Whether to include traceback information

    Returns:
        Standardized error response dictionary
    """
    response = {
        "success": False,
        "error": {
            "type": error.__class__.__name__,
            "code": error.error_code,
            "message": error.message,
            "timestamp": error.timestamp.isoformat(),
            "details": error.details,
        },
    }

    if include_traceback and error.traceback_info:
        response["error"]["traceback"] = error.traceback_info

    if error.cause:
        response["error"]["cause"] = str(error.cause)

    return response


# Exception registry for error code mapping
ERROR_CODE_REGISTRY = {
    "CONFIG_ERROR": ConfigurationError,
    "DB_ERROR": DatabaseError,
    "DB_CONNECTION_ERROR": ConnectionError,
    "DB_QUERY_ERROR": QueryError,
    "SCAN_ERROR": ScanError,
    "FILE_ACCESS_ERROR": FileAccessError,
    "MALWARE_DETECTED": MalwareDetectedError,
    "QUARANTINE_ERROR": QuarantineError,
    "QUARANTINE_ACCESS_ERROR": QuarantineAccessError,
    "ENCRYPTION_ERROR": EncryptionError,
    "SIGNATURE_ERROR": SignatureError,
    "UPDATE_ERROR": UpdateError,
    "NETWORK_ERROR": NetworkError,
    "AUTH_ERROR": AuthenticationError,
    "AUTHZ_ERROR": AuthorizationError,
    "VALIDATION_ERROR": ValidationError,
    "RESOURCE_ERROR": ResourceError,
    "MEMORY_ERROR": MemoryError,
    "DISK_SPACE_ERROR": DiskSpaceError,
    "TIMEOUT_ERROR": TimeoutError,
    "CRITICAL_ERROR": CriticalError,
}


def get_exception_class(error_code: str) -> type:
    """Get exception class by error code"""
    return ERROR_CODE_REGISTRY.get(error_code, AntivirusError)


def create_exception_from_code(
    error_code: str, message: str, **kwargs
) -> AntivirusError:
    """Create exception instance from error code"""
    exception_class = get_exception_class(error_code)
    return exception_class(message, **kwargs)
