"""
Error Management System for EV Charging Simulation.

Provides centralized error handling, tracking, and display across all modules.
Errors are captured with context and displayed in a user-friendly manner on
both Central and Driver (Front-end) dashboards.

Error Categories:
- CONNECTION: Network/connectivity issues (Central, Registry, Weather)
- COMMUNICATION: Message parsing, protocol errors
- CP_UNAVAILABLE: Charging point out of service
- AUTHENTICATION: Security/credential errors
- SERVICE: External service failures (Weather API, Registry)
- SESSION: Charging session errors
- SYSTEM: Internal system errors
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from loguru import logger

from evcharging.common.utils import utc_now


class ErrorCategory(str, Enum):
    """Categories of errors in the system."""
    CONNECTION = "CONNECTION"           # Network connectivity issues
    COMMUNICATION = "COMMUNICATION"     # Message parsing/protocol errors
    CP_UNAVAILABLE = "CP_UNAVAILABLE"   # CP out of service
    AUTHENTICATION = "AUTHENTICATION"   # Security/credential errors
    SERVICE = "SERVICE"                 # External service failures
    SESSION = "SESSION"                 # Charging session errors
    SYSTEM = "SYSTEM"                   # Internal system errors


class ErrorSeverity(str, Enum):
    """Severity levels for errors."""
    INFO = "INFO"           # Informational, auto-recoverable
    WARNING = "WARNING"     # Potential issue, degraded functionality
    ERROR = "ERROR"         # Failure requiring attention
    CRITICAL = "CRITICAL"   # System-impacting failure


class ErrorSource(str, Enum):
    """Source components that can generate errors."""
    CENTRAL = "CENTRAL"
    CP_ENGINE = "CP_ENGINE"
    CP_MONITOR = "CP_MONITOR"
    DRIVER = "DRIVER"
    REGISTRY = "REGISTRY"
    WEATHER = "WEATHER"
    KAFKA = "KAFKA"


@dataclass
class SystemError:
    """
    Represents a system error with full context.
    
    Attributes:
        error_id: Unique identifier for the error
        category: Error category (CONNECTION, COMMUNICATION, etc.)
        severity: Error severity level
        source: Component that generated the error
        target: Affected component/resource (e.g., CP-001)
        message: User-friendly error message
        technical_detail: Technical details for debugging
        timestamp: When the error occurred
        resolved: Whether the error has been resolved
        resolved_at: When the error was resolved
        resolution_message: How the error was resolved
        display_count: How many times this error has been shown
    """
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    source: ErrorSource
    target: str
    message: str
    technical_detail: Optional[str] = None
    timestamp: datetime = field(default_factory=utc_now)
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolution_message: Optional[str] = None
    display_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "error_id": self.error_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "source": self.source.value,
            "target": self.target,
            "message": self.message,
            "technical_detail": self.technical_detail,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_message": self.resolution_message,
        }
    
    def get_display_message(self) -> str:
        """Get formatted message for UI display."""
        return f"{self.message}"
    
    def get_full_message(self) -> str:
        """Get full message including technical details."""
        if self.technical_detail:
            return f"{self.message}\n[Technical: {self.technical_detail}]"
        return self.message


class ErrorManager:
    """
    Centralized error manager for tracking and displaying errors.
    
    Thread-safe error registry that maintains error history and provides
    methods for error reporting, resolution, and display.
    """
    
    _instance: Optional['ErrorManager'] = None
    
    def __init__(self, max_errors: int = 100, max_resolved: int = 50):
        """
        Initialize error manager.
        
        Args:
            max_errors: Maximum active errors to keep
            max_resolved: Maximum resolved errors to keep in history
        """
        self._active_errors: Dict[str, SystemError] = {}
        self._error_history: deque = deque(maxlen=max_resolved)
        self._error_counter = 0
        self._max_errors = max_errors
        
        # Deduplication tracking (same error shouldn't be reported repeatedly)
        self._recent_error_keys: deque = deque(maxlen=50)
        
        # Callbacks for error notifications
        self._error_callbacks: List[callable] = []
    
    @classmethod
    def get_instance(cls) -> 'ErrorManager':
        """Get singleton instance of ErrorManager."""
        if cls._instance is None:
            cls._instance = ErrorManager()
        return cls._instance
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID."""
        self._error_counter += 1
        return f"ERR-{self._error_counter:06d}"
    
    def _get_dedup_key(self, category: ErrorCategory, source: ErrorSource, 
                       target: str, message: str) -> str:
        """Generate deduplication key for an error."""
        return f"{category.value}:{source.value}:{target}:{message[:50]}"
    
    def report_error(
        self,
        category: ErrorCategory,
        source: ErrorSource,
        target: str,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        technical_detail: Optional[str] = None,
        deduplicate: bool = True
    ) -> SystemError:
        """
        Report a new error.
        
        Args:
            category: Error category
            source: Component reporting the error
            target: Affected component/resource
            message: User-friendly error message
            severity: Error severity
            technical_detail: Technical details for debugging
            deduplicate: Whether to skip duplicate errors
            
        Returns:
            The created SystemError
        """
        # Deduplication check
        if deduplicate:
            dedup_key = self._get_dedup_key(category, source, target, message)
            if dedup_key in self._recent_error_keys:
                # Find existing error and increment display count
                for error in self._active_errors.values():
                    if (error.category == category and error.source == source 
                        and error.target == target and not error.resolved):
                        error.display_count += 1
                        return error
            self._recent_error_keys.append(dedup_key)
        
        # Create new error
        error = SystemError(
            error_id=self._generate_error_id(),
            category=category,
            severity=severity,
            source=source,
            target=target,
            message=message,
            technical_detail=technical_detail,
        )
        
        # Store error
        self._active_errors[error.error_id] = error
        
        # Trim if too many errors
        if len(self._active_errors) > self._max_errors:
            oldest_id = next(iter(self._active_errors))
            del self._active_errors[oldest_id]
        
        # Log the error
        log_method = {
            ErrorSeverity.INFO: logger.info,
            ErrorSeverity.WARNING: logger.warning,
            ErrorSeverity.ERROR: logger.error,
            ErrorSeverity.CRITICAL: logger.critical,
        }.get(severity, logger.error)
        
        log_method(f"[{source.value}→{target}] {message}")
        if technical_detail:
            logger.debug(f"Technical detail: {technical_detail}")
        
        # Notify callbacks
        for callback in self._error_callbacks:
            try:
                callback(error)
            except Exception as e:
                logger.warning(f"Error callback failed: {e}")
        
        return error
    
    def resolve_error(
        self,
        error_id: str,
        resolution_message: Optional[str] = None
    ) -> bool:
        """
        Mark an error as resolved.
        
        Args:
            error_id: ID of error to resolve
            resolution_message: How the error was resolved
            
        Returns:
            True if error was found and resolved
        """
        if error_id in self._active_errors:
            error = self._active_errors[error_id]
            error.resolved = True
            error.resolved_at = utc_now()
            error.resolution_message = resolution_message
            
            # Move to history
            self._error_history.append(error)
            del self._active_errors[error_id]
            
            logger.info(f"Error {error_id} resolved: {resolution_message or 'No details'}")
            return True
        return False
    
    def resolve_errors_for_target(
        self,
        target: str,
        category: Optional[ErrorCategory] = None,
        resolution_message: Optional[str] = None
    ) -> int:
        """
        Resolve all errors for a specific target.
        
        Args:
            target: Target to resolve errors for (e.g., CP-001)
            category: Optional category filter
            resolution_message: Resolution message
            
        Returns:
            Number of errors resolved
        """
        resolved_count = 0
        errors_to_resolve = []
        
        for error_id, error in self._active_errors.items():
            if error.target == target and not error.resolved:
                if category is None or error.category == category:
                    errors_to_resolve.append(error_id)
        
        for error_id in errors_to_resolve:
            if self.resolve_error(error_id, resolution_message):
                resolved_count += 1
        
        return resolved_count
    
    def get_active_errors(
        self,
        source: Optional[ErrorSource] = None,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        target: Optional[str] = None
    ) -> List[SystemError]:
        """
        Get active (unresolved) errors with optional filtering.
        
        Args:
            source: Filter by source component
            category: Filter by category
            severity: Filter by severity
            target: Filter by target
            
        Returns:
            List of matching errors
        """
        errors = []
        for error in self._active_errors.values():
            if error.resolved:
                continue
            if source and error.source != source:
                continue
            if category and error.category != category:
                continue
            if severity and error.severity != severity:
                continue
            if target and error.target != target:
                continue
            errors.append(error)
        
        # Sort by severity (most severe first) then by timestamp (newest first)
        severity_order = {
            ErrorSeverity.CRITICAL: 0,
            ErrorSeverity.ERROR: 1,
            ErrorSeverity.WARNING: 2,
            ErrorSeverity.INFO: 3,
        }
        errors.sort(key=lambda e: (severity_order.get(e.severity, 99), -e.timestamp.timestamp()))
        
        return errors
    
    def get_error_history(self, limit: int = 20) -> List[SystemError]:
        """Get resolved errors from history."""
        return list(self._error_history)[-limit:]
    
    def get_errors_for_display(
        self,
        source: Optional[ErrorSource] = None,
        include_resolved: bool = False,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get errors formatted for dashboard display.
        
        Args:
            source: Filter by source component
            include_resolved: Include resolved errors
            limit: Maximum errors to return
            
        Returns:
            List of error dictionaries
        """
        errors = self.get_active_errors(source=source)[:limit]
        
        if include_resolved:
            history = [e for e in self.get_error_history(limit) 
                      if source is None or e.source == source]
            errors = errors + history
        
        return [e.to_dict() for e in errors[:limit]]
    
    def clear_all_errors(self):
        """Clear all active errors (for testing/reset)."""
        for error in list(self._active_errors.values()):
            error.resolved = True
            error.resolved_at = utc_now()
            error.resolution_message = "Cleared by system reset"
            self._error_history.append(error)
        self._active_errors.clear()
    
    def add_error_callback(self, callback: callable):
        """Add callback for error notifications."""
        self._error_callbacks.append(callback)
    
    def remove_error_callback(self, callback: callable):
        """Remove error notification callback."""
        if callback in self._error_callbacks:
            self._error_callbacks.remove(callback)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of current error state."""
        active_errors = self.get_active_errors()
        
        by_severity = {}
        by_category = {}
        by_target = {}
        
        for error in active_errors:
            by_severity[error.severity.value] = by_severity.get(error.severity.value, 0) + 1
            by_category[error.category.value] = by_category.get(error.category.value, 0) + 1
            by_target[error.target] = by_target.get(error.target, 0) + 1
        
        return {
            "total_active": len(active_errors),
            "total_resolved": len(self._error_history),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_target": by_target,
            "has_critical": any(e.severity == ErrorSeverity.CRITICAL for e in active_errors),
        }


# Convenience functions for common error types
def report_connection_error(
    source: ErrorSource,
    target: str,
    service_name: str,
    detail: Optional[str] = None
) -> SystemError:
    """Report a connection error to a service."""
    manager = ErrorManager.get_instance()
    return manager.report_error(
        category=ErrorCategory.CONNECTION,
        source=source,
        target=target,
        message=f"Unable to connect to {service_name}. {service_name} connection unavailable.",
        severity=ErrorSeverity.ERROR,
        technical_detail=detail
    )


def report_cp_unavailable(
    source: ErrorSource,
    cp_id: str,
    reason: str
) -> SystemError:
    """Report a CP unavailable error."""
    manager = ErrorManager.get_instance()
    return manager.report_error(
        category=ErrorCategory.CP_UNAVAILABLE,
        source=source,
        target=cp_id,
        message=f"CP {cp_id} not available. {reason}",
        severity=ErrorSeverity.WARNING,
        technical_detail=f"CP out of service: {reason}"
    )


def report_communication_error(
    source: ErrorSource,
    target: str,
    component: str,
    detail: Optional[str] = None
) -> SystemError:
    """Report a communication/message parsing error."""
    manager = ErrorManager.get_instance()
    return manager.report_error(
        category=ErrorCategory.COMMUNICATION,
        source=source,
        target=target,
        message=f"Unable to connect to {component}. Messages are incomprehensible.",
        severity=ErrorSeverity.ERROR,
        technical_detail=detail
    )


def report_service_error(
    source: ErrorSource,
    service_name: str,
    detail: Optional[str] = None
) -> SystemError:
    """Report an external service error."""
    manager = ErrorManager.get_instance()
    return manager.report_error(
        category=ErrorCategory.SERVICE,
        source=source,
        target=service_name,
        message=f"Unable to access the {service_name}. {service_name} connection unavailable.",
        severity=ErrorSeverity.ERROR,
        technical_detail=detail
    )


def report_registry_error(
    source: ErrorSource,
    target: str,
    detail: Optional[str] = None
) -> SystemError:
    """Report a registry error."""
    manager = ErrorManager.get_instance()
    return manager.report_error(
        category=ErrorCategory.SERVICE,
        source=source,
        target=target,
        message="Registry not responding.",
        severity=ErrorSeverity.ERROR,
        technical_detail=detail
    )


def resolve_target_errors(target: str, message: Optional[str] = None):
    """Resolve all errors for a target."""
    manager = ErrorManager.get_instance()
    manager.resolve_errors_for_target(target, resolution_message=message)


# Global error manager instance
_error_manager: Optional[ErrorManager] = None


def get_error_manager() -> ErrorManager:
    """Get the global error manager instance."""
    global _error_manager
    if _error_manager is None:
        _error_manager = ErrorManager()
    return _error_manager
