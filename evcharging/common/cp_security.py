"""
CP Security Service for EV_Central.

Provides:
- CP authentication using EV_Registry-issued credentials
- Per-CP symmetric encryption key management
- Key generation, rotation, and revocation
- Status enforcement (ACTIVE, OUT_OF_SERVICE, REVOKED)
- Payload encryption/decryption for CP communication
- Centralized audit logging for all security operations
"""

import secrets
import hashlib
import json
import os
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
    PENDING = "PENDING"
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
        token: Optional[str] = None,
        reason_code: Optional[str] = None  # For audit logging
    ):
        self.success = success
        self.cp_id = cp_id
        self.status = status
        self.reason = reason
        self.token = token
        self.reason_code = reason_code  # Structured reason for audit
    
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
    
    # Key wrapping configuration (class-level)
    _wrapping_key: Optional[bytes] = None
    
    @classmethod
    def initialize_key_wrapping(cls, wrapping_secret: str) -> None:
        """
        Initialize key wrapping with a dedicated secret.
        MUST be called before any key wrapping operations.
        
        Args:
            wrapping_secret: Dedicated secret for key wrapping (min 32 chars)
            
        Raises:
            ValueError: If secret is too short or missing
        """
        if not wrapping_secret:
            raise ValueError(
                "EV_KEY_ENCRYPTION_SECRET is required but not set. "
                "Key wrapping requires a dedicated secret (minimum 32 characters). "
                "DO NOT reuse the JWT signing secret."
            )
        
        if len(wrapping_secret) < 32:
            raise ValueError(
                f"Key wrapping secret is too short ({len(wrapping_secret)} chars). "
                "Minimum 32 characters required for security."
            )
        
        # Derive wrapping key from secret
        salt = b'ev-central-key-wrapping-v1'  # Fixed salt for deterministic key derivation
        cls._wrapping_key = cls.derive_key_from_secret(wrapping_secret, salt)
        logger.info("Key wrapping initialized with dedicated secret")
    
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
    
    @classmethod
    def wrap_key(cls, key: bytes, cp_id: str) -> str:
        """
        Wrap (encrypt) a CP encryption key for secure storage.
        Uses AES-GCM with cp_id as associated data to prevent key swapping.
        
        Args:
            key: Raw encryption key to wrap
            cp_id: CP identifier - used as AAD to bind wrapped key to specific CP
            
        Returns:
            Base64-encoded wrapped key with nonce
            
        Raises:
            ValueError: If key wrapping not initialized
        """
        if cls._wrapping_key is None:
            raise ValueError(
                "Key wrapping not initialized. "
                "Call initialize_key_wrapping() with EV_KEY_ENCRYPTION_SECRET first."
            )
        
        try:
            aesgcm = AESGCM(cls._wrapping_key)
            nonce = secrets.token_bytes(cls.NONCE_SIZE)
            
            # Use cp_id as associated data to bind wrapped key to this CP
            # This prevents wrapped keys from being copied between CPs
            aad = cp_id.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, key, aad)
            
            wrapped_data = nonce + ciphertext
            import base64
            return base64.b64encode(wrapped_data).decode('utf-8')
        
        except Exception as e:
            logger.error(f"Key wrapping failed for CP {cp_id}: {e}")
            raise ValueError(f"Key wrapping failed: {e}")
    
    @classmethod
    def unwrap_key(cls, wrapped_key_b64: str, cp_id: str) -> bytes:
        """
        Unwrap (decrypt) a CP encryption key from storage.
        Validates that cp_id matches the AAD used during wrapping.
        
        Args:
            wrapped_key_b64: Base64-encoded wrapped key
            cp_id: CP identifier - must match the AAD from wrapping
            
        Returns:
            Raw encryption key bytes
            
        Raises:
            ValueError: If unwrapping fails or cp_id doesn't match
        """
        if cls._wrapping_key is None:
            raise ValueError(
                "Key wrapping not initialized. "
                "Call initialize_key_wrapping() with EV_KEY_ENCRYPTION_SECRET first."
            )
        
        try:
            import base64
            wrapped_data = base64.b64decode(wrapped_key_b64)
            
            nonce = wrapped_data[:cls.NONCE_SIZE]
            ciphertext = wrapped_data[cls.NONCE_SIZE:]
            
            # Must provide same cp_id used during wrapping
            aad = cp_id.encode('utf-8')
            
            aesgcm = AESGCM(cls._wrapping_key)
            key = aesgcm.decrypt(nonce, ciphertext, aad)
            
            return key
        
        except Exception as e:
            logger.error(f"Key unwrapping failed for CP {cp_id}: {e}")
            raise ValueError(
                f"Key unwrapping failed for CP {cp_id}. "
                "Key may be corrupted, cp_id may not match, or wrapping secret may have changed."
            )


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
            
        Raises:
            ValueError: If EV_KEY_ENCRYPTION_SECRET is not properly configured
        """
        self.security_db = security_db
        self.registry_db = registry_db
        self.security_manager = security_manager
        self.db_path = db_path
        
        # In-memory cache for active encryption keys (cpId -> key bytes)
        # WARNING: This is sensitive data, handle with care
        self._key_cache: Dict[str, bytes] = {}
        
        # Initialize key wrapping with dedicated secret
        wrapping_secret = os.environ.get("EV_KEY_ENCRYPTION_SECRET")
        if not wrapping_secret:
            raise ValueError(
                "EV_KEY_ENCRYPTION_SECRET environment variable is required. \n"
                "This secret is used to wrap/unwrap CP encryption keys in the database. \n"
                "Generate a secure random secret (minimum 32 characters) and set it as an environment variable. \n"
                "Example: export EV_KEY_ENCRYPTION_SECRET='your-secure-random-secret-min-32-chars' \n"
                "DO NOT reuse the JWT signing secret (EV_SECURITY_SECRET)."
            )
        
        CPEncryptionService.initialize_key_wrapping(wrapping_secret)
        
        # Auto-migrate legacy keys on startup
        self._auto_migrate_legacy_keys()
        
        logger.info("CP Security Service initialized")
    
    def _auto_migrate_legacy_keys(self) -> None:
        """
        Automatically migrate legacy keys during service initialization.
        Legacy keys have key_hash but no encrypted_key (pre-wrapping format).
        
        This ensures all active CPs can encrypt/decrypt immediately after startup
        without manual intervention.
        """
        try:
            unmigrated_cps = self.security_db.get_unmigrated_keys()
            
            if not unmigrated_cps:
                logger.debug("No legacy keys requiring migration")
                return
            
            logger.info(
                f"Starting automatic key migration for {len(unmigrated_cps)} CP(s): {unmigrated_cps}"
            )
            
            migration_success = []
            migration_failed = []
            
            for cp_id in unmigrated_cps:
                try:
                    # Check if CP exists in registry
                    cp_record = self.registry_db.get_cp(cp_id)
                    if not cp_record:
                        logger.warning(
                            f"Skipping migration for {cp_id}: Not found in registry. "
                            "CP must be re-registered before key can be migrated."
                        )
                        migration_failed.append((cp_id, "Not in registry"))
                        continue
                    
                    # Get current security status
                    security_status = self.security_db.get_cp_security_status(cp_id)
                    status_str = security_status['registration_status'] if security_status else 'UNKNOWN'
                    
                    # Force reset to wrap legacy key
                    # This temporarily allows key generation even if not ACTIVE
                    success = self.reset_key_for_cp(cp_id, force=True)
                    
                    if success:
                        logger.info(
                            f"✓ Migrated legacy key for CP {cp_id} (status: {status_str})"
                        )
                        migration_success.append(cp_id)
                    else:
                        logger.error(f"✗ Failed to migrate key for CP {cp_id}")
                        migration_failed.append((cp_id, "Reset failed"))
                
                except Exception as e:
                    logger.error(f"✗ Exception migrating key for CP {cp_id}: {e}")
                    migration_failed.append((cp_id, str(e)))
            
            # Summary
            if migration_success:
                logger.info(
                    f"Key migration completed: {len(migration_success)} successful, "
                    f"{len(migration_failed)} failed"
                )
            
            if migration_failed:
                logger.warning(
                    f"Key migration failures: {migration_failed}. "
                    "These CPs will not be able to encrypt/decrypt until manually fixed."
                )
        
        except Exception as e:
            logger.error(f"Failed to run key migration: {e}")
            # Don't fail startup - just log the error
    
    def _check_key_migration_needed(self) -> None:
        """
        Check if any existing keys need migration to wrapped format.
        Logs warnings for keys that need attention.
        """
        try:
            unmigrated_cps = self.security_db.get_unmigrated_keys()
            if unmigrated_cps:
                logger.warning(
                    f"Found {len(unmigrated_cps)} CP(s) with keys needing migration: {unmigrated_cps}"
                )
                logger.warning(
                    "These CPs have key_hash but no encrypted_key. "
                    "They will need key reset before they can encrypt/decrypt. "
                    "Consider running key migration or reset for these CPs."
                )
        except Exception as e:
            logger.error(f"Failed to check key migration status: {e}")
    
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
        Enforces registry existence and ACTIVE security status.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if key generated successfully
            
        Raises:
            ValueError: If CP not in registry or not ACTIVE
        """
        try:
            # 1. Verify CP exists in registry
            cp_record = self.registry_db.get_cp(cp_id)
            if not cp_record:
                raise ValueError(
                    f"Cannot generate key: CP {cp_id} not found in registry. "
                    "CP must be registered in EV_Registry before key generation."
                )
            
            # 2. Verify CP is registered (not deregistered)
            if cp_record['status'] != 'REGISTERED':
                raise ValueError(
                    f"Cannot generate key: CP {cp_id} registry status is {cp_record['status']}. "
                    "Only REGISTERED CPs can have keys generated."
                )
            
            # 3. Verify security status is ACTIVE
            security_status = self.security_db.get_cp_security_status(cp_id)
            if security_status and security_status['registration_status'] != 'ACTIVE':
                raise ValueError(
                    f"Cannot generate key: CP {cp_id} security status is {security_status['registration_status']}. "
                    "Only ACTIVE CPs can have keys generated. "
                    "REVOKED CPs cannot be restored. OUT_OF_SERVICE CPs must be restored to ACTIVE first."
                )
            
            # 4. Generate secure random key
            key = CPEncryptionService.generate_key()
            key_hash = CPEncryptionService.hash_key(key)
            
            # 5. Wrap key for secure storage (bound to cp_id)
            wrapped_key = CPEncryptionService.wrap_key(key, cp_id)
            
            # 6. Store wrapped key and hash in database
            self.security_db.store_encryption_key(cp_id, key_hash, wrapped_key)
            
            # 7. Cache the key in memory
            self._key_cache[cp_id] = key
            
            logger.info(f"Generated encryption key for CP {cp_id}")
            return True
        
        except ValueError as e:
            # Re-raise validation errors
            logger.error(f"Key generation validation failed for CP {cp_id}: {e}")
            raise
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
    
    def reset_key_for_cp(self, cp_id: str, force: bool = False) -> bool:
        """
        Reset (rotate) a CP's encryption key.
        This revokes the old key and generates a new one.
        
        Args:
            cp_id: Charging point identifier
            force: If True, skip registry/status checks (for migration/recovery)
            
        Returns:
            True if key reset successfully
            
        Raises:
            ValueError: If CP not in registry or not ACTIVE (unless force=True)
        """
        try:
            # Skip checks if force=True (for migration scenarios)
            if not force:
                # Verify CP exists in registry and is ACTIVE
                cp_record = self.registry_db.get_cp(cp_id)
                if not cp_record:
                    raise ValueError(
                        f"Cannot reset key: CP {cp_id} not found in registry."
                    )
                
                security_status = self.security_db.get_cp_security_status(cp_id)
                if security_status and security_status['registration_status'] not in ('ACTIVE', 'OUT_OF_SERVICE'):
                    raise ValueError(
                        f"Cannot reset key: CP {cp_id} security status is {security_status['registration_status']}. "
                        "Only ACTIVE or OUT_OF_SERVICE CPs can have keys reset."
                    )
            else:
                logger.warning(f"Forced key reset for CP {cp_id} - bypassing status checks")
            
            # Revoke old key
            self.revoke_key_for_cp(cp_id)
            
            # For forced reset, temporarily allow key generation even if not strictly ACTIVE
            # This is needed for migration scenarios
            if force:
                # Save current security status
                original_status = self.security_db.get_cp_security_status(cp_id)
                
                # Temporarily set to ACTIVE if needed
                if not original_status or original_status['registration_status'] != 'ACTIVE':
                    self.security_db.set_registration_status(cp_id, 'ACTIVE', 'Temporary for key migration')
                
                try:
                    # Generate key
                    key = CPEncryptionService.generate_key()
                    key_hash = CPEncryptionService.hash_key(key)
                    wrapped_key = CPEncryptionService.wrap_key(key, cp_id)
                    
                    self.security_db.store_encryption_key(cp_id, key_hash, wrapped_key)
                    self._key_cache[cp_id] = key
                    success = True
                finally:
                    # Restore original status if we changed it
                    if original_status and original_status['registration_status'] != 'ACTIVE':
                        self.security_db.set_registration_status(
                            cp_id,
                            original_status['registration_status'],
                            'Status restored after key migration'
                        )
            else:
                # Normal path - let generate_key_for_cp do all checks
                success = self.generate_key_for_cp(cp_id)
            
            if success:
                logger.info(f"Reset encryption key for CP {cp_id}")
            
            return success
        
        except ValueError as e:
            logger.error(f"Key reset validation failed for CP {cp_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to reset key for CP {cp_id}: {e}")
            return False
    
    def get_key_for_cp(self, cp_id: str) -> Optional[bytes]:
        """
        Get encryption key for a CP (from cache or unwrap from storage).
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Encryption key or None if not available
        """
        # Check cache first
        if cp_id in self._key_cache:
            return self._key_cache[cp_id]
        
        # Try to retrieve and unwrap from database
        key_info = self.security_db.get_key_info(cp_id)
        if not key_info:
            logger.error(
                f"No encryption key found for CP {cp_id}. "
                "Key must be generated via generate_key_for_cp() first."
            )
            return None
        
        # Check if we have wrapped key
        wrapped_key = key_info.get('encrypted_key')
        if not wrapped_key:
            logger.error(
                f"CP {cp_id} has key_hash but no encrypted_key. "
                "This key needs migration. Call reset_key_for_cp(cp_id, force=True) "
                "to re-wrap the key."
            )
            return None
        
        # Unwrap the key (validates cp_id binding)
        try:
            key = CPEncryptionService.unwrap_key(wrapped_key, cp_id)
            
            # Verify hash matches (integrity check)
            key_hash = CPEncryptionService.hash_key(key)
            if key_hash != key_info['key_hash']:
                logger.error(
                    f"Key integrity check failed for CP {cp_id}. "
                    "Unwrapped key hash doesn't match stored hash. "
                    "Key may be corrupted."
                )
                return None
            
            # Cache for future use
            self._key_cache[cp_id] = key
            logger.debug(f"Unwrapped and cached key for CP {cp_id}")
            
            return key
        
        except ValueError as e:
            logger.error(f"Failed to unwrap key for CP {cp_id}: {e}")
            return None
    
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
