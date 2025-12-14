"""
Security utilities for EV Registry service.

Provides functions for:
- Credential generation and hashing
- Token creation and validation
- Certificate fingerprint extraction
- Secure random string generation
"""

import secrets
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict
from passlib.context import CryptContext
from jose import jwt, JWTError

from evcharging.common.utils import utc_now


# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecurityManager:
    """Manages security operations for CP registry and authentication."""
    
    def __init__(
        self,
        secret_key: str,
        token_expiration_hours: int = 24,
        jwt_issuer: str = "ev-registry",
        jwt_audience: str = "ev-central"
    ):
        """
        Initialize security manager.
        
        Args:
            secret_key: Secret key for JWT signing
            token_expiration_hours: Token validity duration
            jwt_issuer: JWT issuer claim
            jwt_audience: JWT audience claim
        """
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        
        self.secret_key = secret_key
        self.token_expiration_hours = token_expiration_hours
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience
        self.algorithm = "HS256"
    
    @staticmethod
    def generate_credentials(length: int = 32) -> str:
        """
        Generate a secure random credential string.
        
        Args:
            length: Length of the credential string
            
        Returns:
            Hexadecimal credential string
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_credentials(credentials: str) -> str:
        """
        Hash credentials using bcrypt.
        
        Args:
            credentials: Plain text credentials
            
        Returns:
            Hashed credentials
        """
        return pwd_context.hash(credentials)
    
    @staticmethod
    def verify_credentials(plain_credentials: str, hashed_credentials: str) -> bool:
        """
        Verify credentials against a hash.
        
        Args:
            plain_credentials: Plain text credentials to verify
            hashed_credentials: Hashed credentials from database
            
        Returns:
            True if credentials match
        """
        try:
            return pwd_context.verify(plain_credentials, hashed_credentials)
        except Exception:
            return False
    
    def create_access_token(
        self,
        cp_id: str,
        location: Optional[str] = None,
        token_version: Optional[int] = None,
        additional_claims: Optional[Dict] = None
    ) -> str:
        """
        Create a JWT access token for authenticated CP.
        
        Args:
            cp_id: Charging point identifier
            location: CP location
            token_version: Token version for revocation support
            additional_claims: Optional additional JWT claims
            
        Returns:
            Encoded JWT token
        """
        now = utc_now()
        expire = now + timedelta(hours=self.token_expiration_hours)
        
        claims = {
            "sub": cp_id,
            "type": "cp_access",
            "iss": self.jwt_issuer,
            "aud": self.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "nbf": int(now.timestamp())
        }
        
        if location:
            claims["location"] = location
        
        if token_version is not None:
            claims["token_version"] = token_version
        
        if additional_claims:
            claims.update(additional_claims)
        
        return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
    
    def verify_access_token(self, token: str) -> Optional[Dict]:
        """
        Verify and decode a JWT access token.
        
        Args:
            token: Encoded JWT token
            
        Returns:
            Decoded token claims or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.jwt_issuer,
                audience=self.jwt_audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True
                }
            )
            
            # Verify token type
            if payload.get("type") != "cp_access":
                return None
            
            return payload
        except JWTError:
            return None
        except Exception:
            return None
    
    def verify_access_token_with_version(
        self,
        token: str,
        current_token_version: int
    ) -> Optional[Dict]:
        """
        Verify JWT access token and check token version for revocation.
        
        Args:
            token: Encoded JWT token
            current_token_version: Current token version from database
            
        Returns:
            Decoded token claims or None if invalid/revoked
        """
        payload = self.verify_access_token(token)
        
        if not payload:
            return None
        
        # Check token version - reject if token was issued before current version
        token_version = payload.get("token_version")
        if token_version is None:
            # Old tokens without version are rejected for security
            return None
        
        if token_version < current_token_version:
            # Token has been revoked
            return None
        
        return payload
    
    @staticmethod
    def extract_certificate_fingerprint(cert_pem: str, algorithm: str = "sha256") -> str:
        """
        Extract fingerprint from a PEM certificate.
        
        Args:
            cert_pem: PEM-encoded certificate string
            algorithm: Hash algorithm (sha256, sha1, md5)
            
        Returns:
            Hexadecimal fingerprint string
        """
        try:
            # Remove PEM headers/footers and whitespace
            cert_data = cert_pem.replace("-----BEGIN CERTIFICATE-----", "")
            cert_data = cert_data.replace("-----END CERTIFICATE-----", "")
            cert_data = cert_data.replace("\n", "").replace("\r", "").strip()
            
            # Decode base64 and hash
            import base64
            cert_bytes = base64.b64decode(cert_data)
            
            if algorithm == "sha256":
                fingerprint = hashlib.sha256(cert_bytes).hexdigest()
            elif algorithm == "sha1":
                fingerprint = hashlib.sha1(cert_bytes).hexdigest()
            elif algorithm == "md5":
                fingerprint = hashlib.md5(cert_bytes).hexdigest()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Format with colons (e.g., AA:BB:CC:DD:...)
            return ":".join([fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2)])
        
        except Exception as e:
            raise ValueError(f"Failed to extract certificate fingerprint: {e}")
    
    @staticmethod
    def validate_cp_id(cp_id: str) -> bool:
        """
        Validate CP ID format.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if valid
        """
        if not cp_id or not isinstance(cp_id, str):
            return False
        
        # Must be non-empty, alphanumeric with hyphens/underscores
        if len(cp_id) < 3 or len(cp_id) > 64:
            return False
        
        # Check characters
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        return all(c in allowed_chars for c in cp_id)
    
    @staticmethod
    def validate_location(location: str) -> bool:
        """
        Validate location string.
        
        Args:
            location: Location description
            
        Returns:
            True if valid
        """
        if not location or not isinstance(location, str):
            return False
        
        return 2 <= len(location) <= 256


def create_security_manager(
    secret_key: str,
    token_expiration_hours: int = 24,
    jwt_issuer: str = "ev-registry",
    jwt_audience: str = "ev-central"
) -> SecurityManager:
    """
    Factory function to create a SecurityManager instance.
    
    Args:
        secret_key: Secret key for JWT signing
        token_expiration_hours: Token validity duration
        jwt_issuer: JWT issuer claim
        jwt_audience: JWT audience claim
        
    Returns:
        Configured SecurityManager instance
    """
    return SecurityManager(secret_key, token_expiration_hours, jwt_issuer, jwt_audience)


def validate_admin_key(provided_key: Optional[str], expected_key: Optional[str]) -> bool:
    """
    Validate admin API key in constant time.
    
    Args:
        provided_key: Key provided in request
        expected_key: Expected admin key from config
        
    Returns:
        True if keys match
    """
    if not expected_key or not provided_key:
        return False
    
    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(provided_key, expected_key)
