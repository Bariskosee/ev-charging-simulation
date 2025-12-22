"""
Encrypted Kafka message handlers for secure CP-Central communication.

Provides:
- Per-CP symmetric encryption for Kafka messages
- Encryption error tracking and notification
- Automatic recovery when keys are corrected
- Error display on relevant interfaces

Requirements addressed:
- Messages published/consumed in Topics use symmetric encryption
- Encryption keys don't reside in code (loaded from secure storage)
- Symmetric keys are different for each CP_E
- Key mismatch errors displayed on all relevant interfaces
- System recovers once keys are correct again
"""

import json
from typing import Optional, Dict, Any, Callable, Tuple
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from loguru import logger

from evcharging.common.cp_security import CPEncryptionService
from evcharging.common.utils import utc_now


class EncryptionErrorType(str, Enum):
    """Types of encryption errors."""
    KEY_NOT_FOUND = "key_not_found"
    KEY_MISMATCH = "key_mismatch"
    DECRYPTION_FAILED = "decryption_failed"
    ENCRYPTION_FAILED = "encryption_failed"
    INVALID_FORMAT = "invalid_format"


@dataclass
class EncryptionError:
    """Represents an encryption/decryption error for a CP."""
    cp_id: str
    error_type: EncryptionErrorType
    message: str
    timestamp: datetime = field(default_factory=utc_now)
    is_resolved: bool = False
    resolved_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API/UI display."""
        return {
            "cp_id": self.cp_id,
            "error_type": self.error_type.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "is_resolved": self.is_resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None
        }


class EncryptionErrorTracker:
    """
    Tracks encryption errors per CP for display on interfaces.
    Singleton pattern to share state across components.
    """
    
    _instance: Optional["EncryptionErrorTracker"] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize tracker state."""
        # Active errors by CP ID
        self._errors: Dict[str, EncryptionError] = {}
        # Error callbacks for real-time notification
        self._callbacks: list[Callable[[EncryptionError], None]] = []
        # Recovery callbacks
        self._recovery_callbacks: list[Callable[[str], None]] = []
        # Error history (last N errors)
        self._history: list[EncryptionError] = []
        self._max_history = 100
    
    def record_error(
        self,
        cp_id: str,
        error_type: EncryptionErrorType,
        message: str
    ) -> EncryptionError:
        """
        Record an encryption error for a CP.
        
        Args:
            cp_id: Charging point identifier
            error_type: Type of encryption error
            message: Human-readable error message
            
        Returns:
            The recorded error
        """
        error = EncryptionError(
            cp_id=cp_id,
            error_type=error_type,
            message=message
        )
        
        # Store as active error
        self._errors[cp_id] = error
        
        # Add to history
        self._history.append(error)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
        
        # Log the error
        logger.error(
            f"ENCRYPTION ERROR [{cp_id}]: {error_type.value} - {message}"
        )
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(error)
            except Exception as e:
                logger.error(f"Error callback failed: {e}")
        
        return error
    
    def resolve_error(self, cp_id: str) -> bool:
        """
        Mark an error as resolved (key corrected).
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if an error was resolved
        """
        if cp_id not in self._errors:
            return False
        
        error = self._errors[cp_id]
        error.is_resolved = True
        error.resolved_at = utc_now()
        
        # Remove from active errors
        del self._errors[cp_id]
        
        logger.info(
            f"ENCRYPTION RECOVERED [{cp_id}]: Communication restored"
        )
        
        # Notify recovery callbacks
        for callback in self._recovery_callbacks:
            try:
                callback(cp_id)
            except Exception as e:
                logger.error(f"Recovery callback failed: {e}")
        
        return True
    
    def has_error(self, cp_id: str) -> bool:
        """Check if CP has an active encryption error."""
        return cp_id in self._errors
    
    def get_error(self, cp_id: str) -> Optional[EncryptionError]:
        """Get active error for a CP."""
        return self._errors.get(cp_id)
    
    def get_all_errors(self) -> Dict[str, EncryptionError]:
        """Get all active encryption errors."""
        return self._errors.copy()
    
    def get_error_list(self) -> list[Dict]:
        """Get all active errors as list of dicts for API."""
        return [e.to_dict() for e in self._errors.values()]
    
    def get_history(self, limit: int = 50) -> list[Dict]:
        """Get recent error history."""
        return [e.to_dict() for e in self._history[-limit:]]
    
    def register_error_callback(
        self,
        callback: Callable[[EncryptionError], None]
    ):
        """Register callback for error notifications."""
        self._callbacks.append(callback)
    
    def register_recovery_callback(
        self,
        callback: Callable[[str], None]
    ):
        """Register callback for recovery notifications."""
        self._recovery_callbacks.append(callback)
    
    def clear_all(self):
        """Clear all errors (for testing)."""
        self._errors.clear()
        self._history.clear()


# Global tracker instance
def get_encryption_error_tracker() -> EncryptionErrorTracker:
    """Get the global encryption error tracker."""
    return EncryptionErrorTracker()


class EncryptedMessage:
    """
    Wrapper for encrypted Kafka messages.
    
    Message format:
    {
        "cp_id": "CP-001",
        "encrypted": true,
        "payload": "<base64 encrypted data>",
        "ts": "2025-12-22T10:00:00Z"
    }
    
    For backward compatibility, unencrypted messages are also supported:
    {
        "cp_id": "CP-001",
        "encrypted": false,
        "payload": { ... original data ... },
        "ts": "2025-12-22T10:00:00Z"
    }
    """
    
    def __init__(
        self,
        cp_id: str,
        payload: Any,
        encrypted: bool = True,
        ts: Optional[datetime] = None
    ):
        self.cp_id = cp_id
        self.payload = payload
        self.encrypted = encrypted
        self.ts = ts or utc_now()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for Kafka serialization."""
        return {
            "cp_id": self.cp_id,
            "encrypted": self.encrypted,
            "payload": self.payload,
            "ts": self.ts.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "EncryptedMessage":
        """Create from dictionary."""
        return cls(
            cp_id=data["cp_id"],
            payload=data["payload"],
            encrypted=data.get("encrypted", False),
            ts=datetime.fromisoformat(data["ts"]) if "ts" in data else utc_now()
        )


class EncryptedKafkaHandler:
    """
    Handles encryption/decryption for Kafka messages.
    
    Usage:
        handler = EncryptedKafkaHandler(get_key_callback)
        
        # Encrypt before sending
        encrypted_msg = handler.encrypt_message(cp_id, payload)
        
        # Decrypt after receiving
        payload = handler.decrypt_message(encrypted_msg)
    """
    
    def __init__(
        self,
        get_key_for_cp: Callable[[str], Optional[bytes]],
        encryption_enabled: bool = True
    ):
        """
        Initialize handler.
        
        Args:
            get_key_for_cp: Callback to get encryption key for a CP
            encryption_enabled: Global flag to enable/disable encryption
        """
        self._get_key = get_key_for_cp
        self._encryption_enabled = encryption_enabled
        self._tracker = get_encryption_error_tracker()
    
    @property
    def encryption_enabled(self) -> bool:
        """Check if encryption is enabled."""
        return self._encryption_enabled
    
    def encrypt_message(
        self,
        cp_id: str,
        payload: Dict
    ) -> Tuple[Optional[Dict], Optional[EncryptionError]]:
        """
        Encrypt a message payload for a specific CP.
        
        Args:
            cp_id: Target CP identifier
            payload: Dictionary to encrypt
            
        Returns:
            Tuple of (encrypted message dict, error if any)
        """
        if not self._encryption_enabled:
            # Return unencrypted wrapper
            msg = EncryptedMessage(cp_id, payload, encrypted=False)
            return msg.to_dict(), None
        
        # Get encryption key for CP
        key = self._get_key(cp_id)
        if not key:
            error = self._tracker.record_error(
                cp_id,
                EncryptionErrorType.KEY_NOT_FOUND,
                f"No encryption key found for CP {cp_id}. "
                "Key must be generated before encrypted communication."
            )
            return None, error
        
        try:
            # Encrypt payload
            payload_json = json.dumps(payload)
            encrypted_payload = CPEncryptionService.encrypt_payload(payload_json, key)
            
            # Create encrypted message
            msg = EncryptedMessage(cp_id, encrypted_payload, encrypted=True)
            
            # If we had a previous error, mark as resolved
            if self._tracker.has_error(cp_id):
                self._tracker.resolve_error(cp_id)
            
            return msg.to_dict(), None
        
        except Exception as e:
            error = self._tracker.record_error(
                cp_id,
                EncryptionErrorType.ENCRYPTION_FAILED,
                f"Failed to encrypt message for CP {cp_id}: {str(e)}"
            )
            return None, error
    
    def decrypt_message(
        self,
        message: Dict
    ) -> Tuple[Optional[Dict], Optional[EncryptionError]]:
        """
        Decrypt a message received from Kafka.
        
        Args:
            message: Message dictionary from Kafka
            
        Returns:
            Tuple of (decrypted payload dict, error if any)
        """
        try:
            # Parse message wrapper
            if "cp_id" not in message:
                # Legacy format - return as-is
                return message, None
            
            cp_id = message["cp_id"]
            encrypted = message.get("encrypted", False)
            payload = message.get("payload")
            
            if not encrypted:
                # Unencrypted message - return payload directly
                if isinstance(payload, dict):
                    return payload, None
                # Try to parse if string
                if isinstance(payload, str):
                    return json.loads(payload), None
                return payload, None
            
            # Get decryption key
            key = self._get_key(cp_id)
            if not key:
                error = self._tracker.record_error(
                    cp_id,
                    EncryptionErrorType.KEY_NOT_FOUND,
                    f"No decryption key found for CP {cp_id}. "
                    "Cannot decrypt message."
                )
                return None, error
            
            # Decrypt payload
            try:
                decrypted_json = CPEncryptionService.decrypt_payload(payload, key)
                decrypted_payload = json.loads(decrypted_json)
                
                # If we had a previous error, mark as resolved
                if self._tracker.has_error(cp_id):
                    self._tracker.resolve_error(cp_id)
                
                return decrypted_payload, None
            
            except ValueError as e:
                # Decryption failed - likely key mismatch
                error = self._tracker.record_error(
                    cp_id,
                    EncryptionErrorType.KEY_MISMATCH,
                    f"Decryption failed for CP {cp_id}: Key mismatch or corrupted data. "
                    f"Verify encryption keys are synchronized between CP and Central. "
                    f"Error: {str(e)}"
                )
                return None, error
        
        except json.JSONDecodeError as e:
            cp_id = message.get("cp_id", "UNKNOWN")
            error = self._tracker.record_error(
                cp_id,
                EncryptionErrorType.INVALID_FORMAT,
                f"Invalid message format from CP {cp_id}: {str(e)}"
            )
            return None, error
        
        except Exception as e:
            cp_id = message.get("cp_id", "UNKNOWN")
            error = self._tracker.record_error(
                cp_id,
                EncryptionErrorType.DECRYPTION_FAILED,
                f"Unexpected decryption error for CP {cp_id}: {str(e)}"
            )
            return None, error
    
    def is_encrypted_message(self, message: Dict) -> bool:
        """Check if a message is in encrypted format."""
        return (
            isinstance(message, dict) and
            "cp_id" in message and
            "encrypted" in message and
            message.get("encrypted") is True
        )


def create_encrypted_kafka_handler(
    security_service: Any,
    encryption_enabled: bool = True
) -> EncryptedKafkaHandler:
    """
    Factory function to create EncryptedKafkaHandler.
    
    Args:
        security_service: CPSecurityService instance with get_key_for_cp method
        encryption_enabled: Enable/disable encryption globally
        
    Returns:
        Configured EncryptedKafkaHandler
    """
    return EncryptedKafkaHandler(
        get_key_for_cp=security_service.get_key_for_cp,
        encryption_enabled=encryption_enabled
    )
