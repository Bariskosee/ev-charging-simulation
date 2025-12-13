"""
CP Security Service for EV_Central.

Provides:
- CP authentication using EV_Registry-issued credentials
- Per-CP symmetric encryption key management
- Key generation, rotation, and revocation
- Status enforcement (ACTIVE, OUT_OF_SERVICE, REVOKED)
- Payload encryption/decryption for CP communication
"""

import secrets
import hashlib
import json
from typing import Optional, Dict, Tuple
from enum import Enum
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from loguru import logger

from evcharging.common.database import CPSecurityDB, CPRegistryDB
from evcharging.common.security import SecurityManager
from evcharging.common.utils import utc_now


class CPSecurityStatus(str, Enum):
    """CP security registration status."""
    ACTIVE = "ACTIVE"
    OUT_OF_SERVICE = "OUT_OF_SERVICE"
    REVOKED = "REVOKED"


class CPAuthResult:
    """Result of CP authentication attempt."""
    
    def __init__(
        self,
        success: bool,
        cp_id: str,
        status: Optional[CPSecurityStatus] = None,
        reason: Optional[str] = None,
        token: Optional[str] = None
    ):
        self.success = success
        self.cp_id = cp_id
        self.status = status
        self.reason = reason
        self.token = token
    
    def is_authorized(self) -> bool:
        """Check if CP is authorized for operations."""
        return self.success and self.status == CPSecurityStatus.ACTIVE
    
    def __repr__(self) -> str:
        return f"CPAuthResult(success={self.success}, cp_id={self.cp_id}, status={self.status})"


class CPEncryptionService:
    """Handles encryption/decryption for CP communication."""
    
    # AES-GCM provides authenticated encryption
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits (recommended for AES-GCM)
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a secure random encryption key.
        
        Returns:
            32-byte encryption key
        """
        return secrets.token_bytes(CPEncryptionService.KEY_SIZE)
    
    @staticmethod
    def hash_key(key: bytes) -> str:
        """
        Hash an encryption key for secure storage.
        
        Args:
            key: Raw encryption key bytes
            
        Returns:
            SHA-256 hash of the key (hexadecimal)
        """
        return hashlib.sha256(key).hexdigest()
    
    @staticmethod
    def derive_key_from_secret(secret: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a secret using PBKDF2.
        
        Args:
            secret: Secret string
            salt: Random salt
            
        Returns:
            Derived 32-byte key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CPEncryptionService.KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(secret.encode('utf-8'))
    
    @staticmethod
    def encrypt_payload(plaintext: str, key: bytes) -> str:
        """
        Encrypt a payload using AES-GCM.
        
        Args:
            plaintext: Data to encrypt (JSON string)
            key: 32-byte encryption key
            
        Returns:
            Base64-encoded encrypted payload with nonce prefix
            Format: nonce(12 bytes) || ciphertext || tag
        """
        try:
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(CPEncryptionService.NONCE_SIZE)
            
            # Encrypt and authenticate
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            
            # Combine nonce + ciphertext (ciphertext already includes auth tag)
            encrypted_data = nonce + ciphertext
            
            # Return as base64 for transport
            import base64
            return base64.b64encode(encrypted_data).decode('utf-8')
        
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError("Encryption failed")
    
    @staticmethod
    def decrypt_payload(encrypted_b64: str, key: bytes) -> str:
        """
        Decrypt a payload using AES-GCM.
        
        Args:
            encrypted_b64: Base64-encoded encrypted data
            key: 32-byte encryption key
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            ValueError: If decryption fails (wrong key, tampered data, etc.)
        """
        try:
            import base64
            encrypted_data = base64.b64decode(encrypted_b64)
            
            # Extract nonce and ciphertext
            nonce = encrypted_data[:CPEncryptionService.NONCE_SIZE]
            ciphertext = encrypted_data[CPEncryptionService.NONCE_SIZE:]
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed - invalid key or corrupted data")


class CPSecurityService:
    """
    Central security service for CP authentication and key management.
    Integrates with EV_Registry credentials.
    """
    
    def __init__(
        self,
        security_db: CPSecurityDB,
        registry_db: CPRegistryDB,
        security_manager: SecurityManager,
        db_path: str = "ev_charging.db"
    ):
        """
        Initialize CP security service.
        
        Args:
            security_db: Database for security operations
            registry_db: Database for registry lookups
            security_manager: Security manager for token operations
            db_path: Path to database
        """
        self.security_db = security_db
        self.registry_db = registry_db
        self.security_manager = security_manager
        self.db_path = db_path
        
        # In-memory cache for active encryption keys (cpId -> key bytes)
        # WARNING: This is sensitive data, handle with care
        self._key_cache: Dict[str, bytes] = {}
        
        logger.info("CP Security Service initialized")
    
    # ==================== Authentication ====================
    
    def authenticate_cp(self, cp_id: str, credentials: str) -> CPAuthResult:
        """
        Authenticate a CP using EV_Registry-issued credentials.
        
        Args:
            cp_id: Charging point identifier
            credentials: Secret credentials from registration
            
        Returns:
            CPAuthResult with authentication outcome
        """
        try:
            # 1. Check if CP exists in registry
            cp_record = self.registry_db.get_cp(cp_id)
            if not cp_record:
                logger.warning(f"Authentication failed: CP {cp_id} not found in registry")
                return CPAuthResult(
                    success=False,
                    cp_id=cp_id,
                    reason="CP not registered in EV_Registry"
                )
            
            # 2. Check registry status
            if cp_record['status'] != 'REGISTERED':
                logger.warning(f"Authentication failed: CP {cp_id} is {cp_record['status']}")
                return CPAuthResult(
                    success=False,
                    cp_id=cp_id,
                    reason=f"CP status in registry: {cp_record['status']}"
                )
            
            # 3. Verify credentials
            credentials_hash = self.registry_db.get_cp_credentials(cp_id)
            if not credentials_hash:
                logger.error(f"Authentication failed: No credentials for CP {cp_id}")
                return CPAuthResult(
                    success=False,
                    cp_id=cp_id,
                    reason="Credentials not found"
                )
            
            if not self.security_manager.verify_credentials(credentials, credentials_hash):
                logger.warning(f"Authentication failed: Invalid credentials for CP {cp_id}")
                self.security_db.record_auth_failure(cp_id)
                return CPAuthResult(
                    success=False,
                    cp_id=cp_id,
                    reason="Invalid credentials"
                )
            
            # 4. Check security status in EV_Central
            security_status = self.security_db.get_cp_security_status(cp_id)
            if not security_status:
                # Initialize security status if not exists
                self.security_db.initialize_cp_security(cp_id)
                security_status = self.security_db.get_cp_security_status(cp_id)
            
            status_enum = CPSecurityStatus(security_status['registration_status'])
            
            # 5. Enforce status rules
            if status_enum == CPSecurityStatus.REVOKED:
                logger.warning(f"Authentication rejected: CP {cp_id} is REVOKED")
                return CPAuthResult(
                    success=True,  # Credentials are valid
                    cp_id=cp_id,
                    status=status_enum,
                    reason=f"CP revoked: {security_status.get('revocation_reason', 'Unknown')}"
                )
            
            if status_enum == CPSecurityStatus.OUT_OF_SERVICE:
                logger.info(f"Authentication succeeded but CP {cp_id} is OUT_OF_SERVICE")
                return CPAuthResult(
                    success=True,
                    cp_id=cp_id,
                    status=status_enum,
                    reason=f"CP out of service: {security_status.get('out_of_service_reason', 'Maintenance')}"
                )
            
            # 6. Generate access token
            token = self.security_manager.create_access_token(
                cp_id=cp_id,
                location=cp_record.get('location'),
                additional_claims={"status": status_enum.value}
            )
            
            # 7. Record successful authentication
            self.security_db.record_successful_auth(cp_id)
            self.registry_db.update_last_authenticated(cp_id)
            
            logger.info(f"CP {cp_id} authenticated successfully (status: {status_enum.value})")
            
            return CPAuthResult(
                success=True,
                cp_id=cp_id,
                status=status_enum,
                token=token,
                reason="Authentication successful"
            )
        
        except Exception as e:
            logger.error(f"Authentication error for CP {cp_id}: {e}")
            return CPAuthResult(
                success=False,
                cp_id=cp_id,
                reason=f"Internal authentication error: {str(e)}"
            )
    
    def verify_token(self, token: str) -> Optional[CPAuthResult]:
        """
        Verify a JWT token and return authentication result.
        
        Args:
            token: JWT access token
            
        Returns:
            CPAuthResult if valid, None otherwise
        """
        try:
            payload = self.security_manager.verify_access_token(token)
            if not payload:
                return None
            
            cp_id = payload.get('sub')
            if not cp_id:
                return None
            
            # Check current security status
            security_status = self.security_db.get_cp_security_status(cp_id)
            if not security_status:
                return None
            
            status_enum = CPSecurityStatus(security_status['registration_status'])
            
            return CPAuthResult(
                success=True,
                cp_id=cp_id,
                status=status_enum,
                token=token,
                reason="Token valid"
            )
        
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    # ==================== Key Management ====================
    
    def generate_key_for_cp(self, cp_id: str) -> bool:
        """
        Generate a new encryption key for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if key generated successfully
        """
        try:
            # Generate secure random key
            key = CPEncryptionService.generate_key()
            key_hash = CPEncryptionService.hash_key(key)
            
            # Store hash in database
            self.security_db.store_encryption_key(cp_id, key_hash)
            
            # Cache the key in memory
            self._key_cache[cp_id] = key
            
            logger.info(f"Generated encryption key for CP {cp_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to generate key for CP {cp_id}: {e}")
            return False
    
    def revoke_key_for_cp(self, cp_id: str) -> bool:
        """
        Revoke a CP's encryption key.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if key revoked successfully
        """
        try:
            # Remove from cache
            if cp_id in self._key_cache:
                del self._key_cache[cp_id]
            
            # Revoke in database
            success = self.security_db.revoke_encryption_key(cp_id)
            
            if success:
                logger.warning(f"Revoked encryption key for CP {cp_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to revoke key for CP {cp_id}: {e}")
            return False
    
    def reset_key_for_cp(self, cp_id: str) -> bool:
        """
        Reset (rotate) a CP's encryption key.
        First revokes the old key, then generates a new one.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if key reset successfully
        """
        try:
            # Revoke old key
            self.revoke_key_for_cp(cp_id)
            
            # Generate new key
            success = self.generate_key_for_cp(cp_id)
            
            if success:
                logger.info(f"Reset encryption key for CP {cp_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to reset key for CP {cp_id}: {e}")
            return False
    
    def get_key_for_cp(self, cp_id: str) -> Optional[bytes]:
        """
        Get the encryption key for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Encryption key bytes or None if not found
        """
        # Check cache first
        if cp_id in self._key_cache:
            return self._key_cache[cp_id]
        
        # Note: In production, keys should be loaded from secure storage (HSM, KMS, etc.)
        # For this implementation, keys are generated on-demand and cached
        logger.warning(f"Key for CP {cp_id} not in cache - generating new key")
        self.generate_key_for_cp(cp_id)
        
        return self._key_cache.get(cp_id)
    
    # ==================== Encryption Operations ====================
    
    def encrypt_for_cp(self, cp_id: str, payload: Dict) -> Optional[str]:
        """
        Encrypt a payload for a specific CP.
        
        Args:
            cp_id: Target CP identifier
            payload: Dictionary to encrypt
            
        Returns:
            Encrypted payload (base64) or None if failed
        """
        try:
            key = self.get_key_for_cp(cp_id)
            if not key:
                logger.error(f"Cannot encrypt: no key for CP {cp_id}")
                return None
            
            payload_json = json.dumps(payload)
            encrypted = CPEncryptionService.encrypt_payload(payload_json, key)
            
            logger.debug(f"Encrypted payload for CP {cp_id}")
            return encrypted
        
        except Exception as e:
            logger.error(f"Encryption failed for CP {cp_id}: {e}")
            return None
    
    def decrypt_from_cp(self, cp_id: str, encrypted_payload: str) -> Optional[Dict]:
        """
        Decrypt a payload from a specific CP.
        
        Args:
            cp_id: Source CP identifier
            encrypted_payload: Encrypted payload (base64)
            
        Returns:
            Decrypted dictionary or None if failed
        """
        try:
            key = self.get_key_for_cp(cp_id)
            if not key:
                logger.error(f"Cannot decrypt: no key for CP {cp_id}")
                return None
            
            payload_json = CPEncryptionService.decrypt_payload(encrypted_payload, key)
            payload = json.loads(payload_json)
            
            logger.debug(f"Decrypted payload from CP {cp_id}")
            return payload
        
        except Exception as e:
            logger.error(f"Decryption failed for CP {cp_id}: {e}")
            return None
    
    # ==================== Status Management ====================
    
    def revoke_cp(self, cp_id: str, reason: str = "Manual revocation") -> bool:
        """
        Revoke a CP (CRITICAL - blocks all operations).
        
        Args:
            cp_id: Charging point identifier
            reason: Revocation reason
            
        Returns:
            True if revoked successfully
        """
        try:
            # Revoke security status
            success = self.security_db.revoke_cp(cp_id, reason)
            
            # Revoke encryption key
            if success:
                self.revoke_key_for_cp(cp_id)
                logger.warning(f"CP {cp_id} REVOKED: {reason}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to revoke CP {cp_id}: {e}")
            return False
    
    def set_out_of_service(self, cp_id: str, reason: str = "Maintenance") -> bool:
        """
        Mark a CP as out of service.
        
        Args:
            cp_id: Charging point identifier
            reason: Out-of-service reason
            
        Returns:
            True if updated successfully
        """
        try:
            success = self.security_db.set_out_of_service(cp_id, reason)
            
            if success:
                logger.info(f"CP {cp_id} set to OUT_OF_SERVICE: {reason}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to set CP {cp_id} out of service: {e}")
            return False
    
    def restore_to_active(self, cp_id: str) -> bool:
        """
        Restore a CP from OUT_OF_SERVICE to ACTIVE.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if restored successfully
        """
        try:
            success = self.security_db.restore_to_active(cp_id)
            
            if success:
                logger.info(f"CP {cp_id} restored to ACTIVE")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to restore CP {cp_id}: {e}")
            return False
    
    def get_security_status(self, cp_id: str) -> Optional[CPSecurityStatus]:
        """
        Get the current security status of a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            CPSecurityStatus enum or None
        """
        try:
            status = self.security_db.get_cp_security_status(cp_id)
            if not status:
                return None
            
            return CPSecurityStatus(status['registration_status'])
        
        except Exception as e:
            logger.error(f"Failed to get status for CP {cp_id}: {e}")
            return None
