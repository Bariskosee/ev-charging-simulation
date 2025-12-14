"""
Centralized Audit Service for EV_Central.

Provides a comprehensive audit logging system that records all security-critical
and operational events to a SQLite database. Ensures traceability and compliance
by maintaining a tamper-evident audit trail.

SECURITY RULES:
- Never log credentials, tokens, keys, or decrypted payloads
- Sanitize all metadata before storing
- Do not store full stack traces in database
- Audit writes must not crash the main request flow
"""

import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from loguru import logger

from evcharging.common.database import AuditDB
from evcharging.common.utils import utc_now


class RequestContext(BaseModel):
    """
    Request context for audit logging.
    Captures essential information about the HTTP request.
    """
    request_id: str = Field(..., description="Unique request ID (UUID)")
    ip: str = Field(default="unknown", description="Client IP address")
    endpoint: Optional[str] = Field(None, description="API endpoint path")
    http_method: Optional[str] = Field(None, description="HTTP method (GET, POST, etc.)")
    
    class Config:
        frozen = True  # Make immutable


class AuditService:
    """
    Central audit logging service.
    
    Provides methods to record various security and operational events
    with consistent formatting and metadata handling.
    """
    
    # Action types (enum-like constants)
    ACTION_AUTH_SUCCESS = "AUTH_SUCCESS"
    ACTION_AUTH_FAIL = "AUTH_FAIL"
    ACTION_STATUS_CHANGE = "STATUS_CHANGE"
    ACTION_KEY_RESET = "KEY_RESET"
    ACTION_KEY_REVOKE = "KEY_REVOKE"
    ACTION_KEY_GENERATE = "KEY_GENERATE"
    ACTION_ERROR = "ERROR"
    ACTION_VALIDATION_ERROR = "VALIDATION_ERROR"
    ACTION_INCIDENT = "INCIDENT"
    
    # Severity levels
    SEVERITY_INFO = "INFO"
    SEVERITY_WARN = "WARN"
    SEVERITY_ERROR = "ERROR"
    SEVERITY_CRITICAL = "CRITICAL"
    
    # Reason codes for failures
    REASON_UNKNOWN_CP = "UNKNOWN_CP"
    REASON_INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    REASON_REVOKED = "REVOKED"
    REASON_OUT_OF_SERVICE = "OUT_OF_SERVICE"
    REASON_EXPIRED_TOKEN = "EXPIRED_TOKEN"
    REASON_INVALID_TOKEN = "INVALID_TOKEN"
    REASON_BAD_SIGNATURE = "BAD_SIGNATURE"
    REASON_INVALID_ENCRYPTION = "INVALID_ENCRYPTION"
    REASON_TOKEN_VERSION_MISMATCH = "TOKEN_VERSION_MISMATCH"
    REASON_MISSING_KEY = "MISSING_KEY"
    
    # Incident types
    INCIDENT_BRUTE_FORCE = "BRUTE_FORCE_SUSPECTED"
    INCIDENT_UNAUTHORIZED_ADMIN = "UNAUTHORIZED_ADMIN_ACCESS"
    INCIDENT_TAMPERING = "TAMPERING_DETECTED"
    
    # Brute force detection thresholds
    BRUTE_FORCE_THRESHOLD = 5  # failures
    BRUTE_FORCE_WINDOW_MINUTES = 10
    
    def __init__(self, db_path: str = "ev_charging.db"):
        """
        Initialize audit service.
        
        Args:
            db_path: Path to SQLite database
        """
        self.audit_db = AuditDB(db_path)
    
    def _create_event(
        self,
        who: str,
        ctx: RequestContext,
        action: str,
        description: str,
        severity: str,
        reason_code: Optional[str] = None,
        status_code: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict:
        """
        Create audit event dictionary.
        
        Args:
            who: CP ID, "system", "admin", or "unknown"
            ctx: Request context
            action: Action type
            description: Human-readable description
            severity: Severity level
            reason_code: Optional structured reason code
            status_code: Optional HTTP status code
            metadata: Optional metadata (will be sanitized and JSON-serialized)
        
        Returns:
            Event dictionary ready for database insertion
        """
        event = {
            'date_time': utc_now().isoformat(),
            'who': who,
            'ip': ctx.ip,
            'action': action,
            'description': description,
            'severity': severity,
            'reason_code': reason_code,
            'request_id': ctx.request_id,
            'endpoint': ctx.endpoint,
            'http_method': ctx.http_method,
            'status_code': status_code,
            'metadata_json': self._sanitize_metadata(metadata) if metadata else None
        }
        return event
    
    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> str:
        """
        Sanitize metadata and convert to JSON string.
        
        Removes any sensitive fields and ensures safe serialization.
        
        Args:
            metadata: Metadata dictionary
        
        Returns:
            JSON string (safe for storage)
        """
        # List of field names that should never be logged
        forbidden_keys = {
            'credentials', 'token', 'password', 'secret', 'key', 
            'private_key', 'symmetric_key', 'encryption_key',
            'decrypted', 'plaintext', 'authorization'
        }
        
        safe_metadata = {}
        for key, value in metadata.items():
            # Skip forbidden keys
            if any(forbidden in key.lower() for forbidden in forbidden_keys):
                safe_metadata[key] = "***REDACTED***"
            else:
                # Truncate long strings
                if isinstance(value, str) and len(value) > 500:
                    safe_metadata[key] = value[:500] + "...[truncated]"
                else:
                    safe_metadata[key] = value
        
        try:
            return json.dumps(safe_metadata)
        except Exception as e:
            logger.warning(f"Failed to serialize metadata: {e}")
            return json.dumps({"error": "serialization_failed"})
    
    def _write_event(self, event: Dict) -> bool:
        """
        Write event to database with fallback logging.
        
        Args:
            event: Event dictionary
        
        Returns:
            True if written successfully
        """
        success = self.audit_db.insert_event(event)
        
        if not success:
            # Fallback: log to standard logger but DO NOT expose sensitive data
            logger.error(
                f"AUDIT WRITE FAILED: {event['action']} by {event['who']} "
                f"from {event['ip']} - {event['description']}"
            )
        
        return success
    
    # ========== Authentication Events ==========
    
    def auth_success(
        self,
        cp_id: str,
        ctx: RequestContext,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record successful authentication.
        
        Args:
            cp_id: Charging point ID
            ctx: Request context
            metadata: Optional metadata (security_status, etc.)
        
        Returns:
            True if audit event written successfully
        """
        event = self._create_event(
            who=cp_id,
            ctx=ctx,
            action=self.ACTION_AUTH_SUCCESS,
            description=f"CP {cp_id} authenticated successfully",
            severity=self.SEVERITY_INFO,
            status_code=200,
            metadata=metadata
        )
        return self._write_event(event)
    
    def auth_fail(
        self,
        cp_id_or_unknown: str,
        ctx: RequestContext,
        reason_code: str,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record authentication failure.
        
        Args:
            cp_id_or_unknown: CP ID or "unknown" if CP not identified
            ctx: Request context
            reason_code: Failure reason code
            description: Optional human-readable description
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        desc = description or f"Authentication failed: {reason_code}"
        
        event = self._create_event(
            who=cp_id_or_unknown,
            ctx=ctx,
            action=self.ACTION_AUTH_FAIL,
            description=desc,
            severity=self.SEVERITY_WARN,
            reason_code=reason_code,
            status_code=401,
            metadata=metadata
        )
        return self._write_event(event)
    
    # ========== Status Change Events ==========
    
    def status_change(
        self,
        cp_id: str,
        ctx: RequestContext,
        old_status: str,
        new_status: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record CP status change.
        
        Args:
            cp_id: Charging point ID
            ctx: Request context
            old_status: Previous status
            new_status: New status
            reason: Optional reason for change
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        desc = f"CP {cp_id} status changed from {old_status} to {new_status}"
        if reason:
            desc += f" - Reason: {reason}"
        
        severity = self.SEVERITY_WARN if new_status in ["REVOKED", "OUT_OF_SERVICE"] else self.SEVERITY_INFO
        
        event = self._create_event(
            who=cp_id,
            ctx=ctx,
            action=self.ACTION_STATUS_CHANGE,
            description=desc,
            severity=severity,
            metadata=metadata or {"old_status": old_status, "new_status": new_status, "reason": reason}
        )
        return self._write_event(event)
    
    # ========== Key Operations ==========
    
    def key_reset(
        self,
        cp_id: str,
        ctx: RequestContext,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record encryption key reset operation.
        
        Args:
            cp_id: Charging point ID
            ctx: Request context
            reason: Optional reason
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        desc = f"Encryption key reset for CP {cp_id}"
        if reason:
            desc += f" - Reason: {reason}"
        
        event = self._create_event(
            who=cp_id,
            ctx=ctx,
            action=self.ACTION_KEY_RESET,
            description=desc,
            severity=self.SEVERITY_WARN,
            metadata=metadata
        )
        return self._write_event(event)
    
    def key_revoke(
        self,
        cp_id: str,
        ctx: RequestContext,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record encryption key revocation.
        
        Args:
            cp_id: Charging point ID
            ctx: Request context
            reason: Optional reason
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        desc = f"Encryption key revoked for CP {cp_id}"
        if reason:
            desc += f" - Reason: {reason}"
        
        event = self._create_event(
            who=cp_id,
            ctx=ctx,
            action=self.ACTION_KEY_REVOKE,
            description=desc,
            severity=self.SEVERITY_WARN,
            metadata=metadata
        )
        return self._write_event(event)
    
    def key_generate(
        self,
        cp_id: str,
        ctx: RequestContext,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record encryption key generation.
        
        Args:
            cp_id: Charging point ID
            ctx: Request context
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        event = self._create_event(
            who=cp_id,
            ctx=ctx,
            action=self.ACTION_KEY_GENERATE,
            description=f"Encryption key generated for CP {cp_id}",
            severity=self.SEVERITY_INFO,
            metadata=metadata
        )
        return self._write_event(event)
    
    # ========== Error Events ==========
    
    def validation_error(
        self,
        ctx: RequestContext,
        fields_summary: str,
        who: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record request validation error.
        
        Args:
            ctx: Request context
            fields_summary: Summary of validation errors (field names only)
            who: Who made the request (if known)
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        event = self._create_event(
            who=who,
            ctx=ctx,
            action=self.ACTION_VALIDATION_ERROR,
            description=f"Request validation failed: {fields_summary}",
            severity=self.SEVERITY_WARN,
            status_code=422,
            metadata=metadata
        )
        return self._write_event(event)
    
    def error(
        self,
        ctx: RequestContext,
        error_type: str,
        safe_message: str,
        who: str = "system",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record system error.
        
        Args:
            ctx: Request context
            error_type: Type of error (exception class name)
            safe_message: Safe error message (NO stack traces)
            who: Who triggered the error (if known)
            metadata: Optional metadata
        
        Returns:
            True if audit event written successfully
        """
        event = self._create_event(
            who=who,
            ctx=ctx,
            action=self.ACTION_ERROR,
            description=f"System error: {error_type} - {safe_message}",
            severity=self.SEVERITY_ERROR,
            status_code=500,
            metadata=metadata or {"error_type": error_type}
        )
        return self._write_event(event)
    
    # ========== Security Incidents ==========
    
    def incident(
        self,
        who_or_unknown: str,
        ctx: RequestContext,
        incident_type: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record security incident.
        
        Args:
            who_or_unknown: CP ID or "unknown"
            ctx: Request context
            incident_type: Type of incident
            description: Incident description
            metadata: Optional metadata (failure counts, etc.)
        
        Returns:
            True if audit event written successfully
        """
        event = self._create_event(
            who=who_or_unknown,
            ctx=ctx,
            action=self.ACTION_INCIDENT,
            description=description,
            severity=self.SEVERITY_CRITICAL,
            reason_code=incident_type,
            metadata=metadata
        )
        
        # Also log to standard logger for immediate alerting
        logger.critical(
            f"SECURITY INCIDENT: {incident_type} - {description} "
            f"[who={who_or_unknown}, ip={ctx.ip}, request_id={ctx.request_id}]"
        )
        
        return self._write_event(event)
    
    # ========== Incident Detection ==========
    
    def check_brute_force(
        self,
        ip: Optional[str] = None,
        cp_id: Optional[str] = None
    ) -> bool:
        """
        Check if brute force attack is suspected based on recent failures.
        
        Args:
            ip: IP address to check
            cp_id: CP ID to check
        
        Returns:
            True if brute force suspected
        """
        failures = self.audit_db.get_recent_auth_failures(
            ip=ip,
            cp_id=cp_id,
            minutes=self.BRUTE_FORCE_WINDOW_MINUTES
        )
        
        return len(failures) >= self.BRUTE_FORCE_THRESHOLD
    
    def detect_and_report_brute_force(
        self,
        cp_id_or_unknown: str,
        ctx: RequestContext
    ) -> bool:
        """
        Detect brute force attack and report incident if threshold exceeded.
        
        Args:
            cp_id_or_unknown: CP ID or "unknown"
            ctx: Request context
        
        Returns:
            True if incident was reported
        """
        # Check both IP-based and CP-based failures
        ip_failures = self.audit_db.get_recent_auth_failures(
            ip=ctx.ip,
            minutes=self.BRUTE_FORCE_WINDOW_MINUTES
        )
        
        cp_failures = []
        if cp_id_or_unknown != "unknown":
            cp_failures = self.audit_db.get_recent_auth_failures(
                cp_id=cp_id_or_unknown,
                minutes=self.BRUTE_FORCE_WINDOW_MINUTES
            )
        
        # Report incident if threshold exceeded
        if len(ip_failures) >= self.BRUTE_FORCE_THRESHOLD:
            self.incident(
                who_or_unknown=cp_id_or_unknown,
                ctx=ctx,
                incident_type=self.INCIDENT_BRUTE_FORCE,
                description=(
                    f"Brute force attack suspected: {len(ip_failures)} failures "
                    f"from IP {ctx.ip} in last {self.BRUTE_FORCE_WINDOW_MINUTES} minutes"
                ),
                metadata={
                    "ip": ctx.ip,
                    "failure_count": len(ip_failures),
                    "window_minutes": self.BRUTE_FORCE_WINDOW_MINUTES
                }
            )
            return True
        
        if cp_id_or_unknown != "unknown" and len(cp_failures) >= self.BRUTE_FORCE_THRESHOLD:
            self.incident(
                who_or_unknown=cp_id_or_unknown,
                ctx=ctx,
                incident_type=self.INCIDENT_BRUTE_FORCE,
                description=(
                    f"Brute force attack suspected: {len(cp_failures)} failures "
                    f"for CP {cp_id_or_unknown} in last {self.BRUTE_FORCE_WINDOW_MINUTES} minutes"
                ),
                metadata={
                    "cp_id": cp_id_or_unknown,
                    "failure_count": len(cp_failures),
                    "window_minutes": self.BRUTE_FORCE_WINDOW_MINUTES
                }
            )
            return True
        
        return False


# Global audit service instance (singleton pattern)
_audit_service_instance: Optional[AuditService] = None


def get_audit_service(db_path: str = "ev_charging.db") -> AuditService:
    """
    Get or create global audit service instance.
    
    Args:
        db_path: Path to SQLite database
    
    Returns:
        AuditService instance
    """
    global _audit_service_instance
    
    if _audit_service_instance is None:
        _audit_service_instance = AuditService(db_path)
    
    return _audit_service_instance
