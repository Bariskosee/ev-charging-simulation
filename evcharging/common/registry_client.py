"""
Client for EV_Registry API.

Provides secure communication between CPs and the Registry with:
- CP registration and authentication
- JWT token management
- Automatic token refresh
- Secure credential storage (in memory)
"""

import httpx
from typing import Optional, Dict
from datetime import datetime
from loguru import logger

from evcharging.common.utils import utc_now


class RegistryClient:
    """Client for CP registration and authentication with EV_Registry."""
    
    def __init__(
        self,
        registry_url: str,
        verify_ssl: bool = True,
        admin_api_key: Optional[str] = None
    ):
        """
        Initialize Registry client.
        
        Args:
            registry_url: EV_Registry API base URL (e.g., http://localhost:8080)
            verify_ssl: Verify SSL certificates (disable only for dev)
            admin_api_key: Optional admin API key for new registrations
        """
        self.registry_url = registry_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.admin_api_key = admin_api_key
        
        # Credentials (stored in memory - in production use secure vault)
        self.cp_id: Optional[str] = None
        self.credentials: Optional[str] = None
        self.token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.location: Optional[str] = None
        self.is_registered: bool = False
    
    async def register(
        self,
        cp_id: str,
        location: str,
        metadata: Optional[Dict] = None,
        certificate_pem: Optional[str] = None
    ) -> bool:
        """
        Register this CP with EV_Registry.
        
        Args:
            cp_id: Charging point identifier
            location: CP location (city/address)
            metadata: Optional metadata dict
            certificate_pem: Optional PEM-encoded client certificate
            
        Returns:
            True if registration successful
        """
        registration_data = {
            "cp_id": cp_id,
            "location": location
        }
        
        if metadata:
            registration_data["metadata"] = metadata
        
        if certificate_pem:
            registration_data["certificate_pem"] = certificate_pem
        
        # Build headers
        headers = {"Content-Type": "application/json"}
        if self.admin_api_key:
            headers["X-Registry-API-Key"] = self.admin_api_key
        
        # If re-registering with existing credentials, include them
        if self.credentials:
            headers["X-Existing-Credentials"] = self.credentials
        
        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    f"{self.registry_url}/cp/register",
                    json=registration_data,
                    headers=headers
                )
                
                if response.status_code in (200, 201):
                    data = response.json()
                    self.cp_id = cp_id
                    self.location = location
                    self.credentials = data["credentials"]
                    self.token = data["token"]
                    self.is_registered = True
                    
                    # Parse token expiration
                    try:
                        self.token_expires_at = datetime.fromisoformat(
                            data["token_expires_at"].replace("Z", "+00:00")
                        )
                    except (ValueError, KeyError):
                        self.token_expires_at = None
                    
                    logger.info(
                        f"CP {cp_id} registered successfully with EV_Registry"
                    )
                    logger.debug(
                        f"Token expires at: {self.token_expires_at}"
                    )
                    return True
                else:
                    error_detail = response.text
                    try:
                        error_json = response.json()
                        error_detail = error_json.get("detail", error_detail)
                    except Exception:
                        pass
                    
                    logger.error(
                        f"Registration failed: {response.status_code} - {error_detail}"
                    )
                    return False
        
        except httpx.ConnectError as e:
            logger.warning(f"Cannot connect to EV_Registry at {self.registry_url}: {e}")
            return False
        except httpx.TimeoutException:
            logger.warning(f"Timeout connecting to EV_Registry at {self.registry_url}")
            return False
        except Exception as e:
            logger.error(f"Error registering with EV_Registry: {e}")
            return False
    
    async def authenticate(self) -> bool:
        """
        Authenticate and get fresh token.
        
        Returns:
            True if authentication successful
        """
        if not self.cp_id or not self.credentials:
            logger.error("Cannot authenticate: not registered")
            return False
        
        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    f"{self.registry_url}/cp/authenticate",
                    json={
                        "cp_id": self.cp_id,
                        "credentials": self.credentials
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.token = data["token"]
                    
                    # Parse token expiration
                    try:
                        self.token_expires_at = datetime.fromisoformat(
                            data["token_expires_at"].replace("Z", "+00:00")
                        )
                    except (ValueError, KeyError):
                        self.token_expires_at = None
                    
                    logger.info(f"CP {self.cp_id} authenticated successfully")
                    return True
                else:
                    logger.error(
                        f"Authentication failed: {response.status_code} - {response.text}"
                    )
                    return False
        
        except httpx.ConnectError as e:
            logger.warning(f"Cannot connect to EV_Registry: {e}")
            return False
        except Exception as e:
            logger.error(f"Error authenticating with EV_Registry: {e}")
            return False
    
    def get_token(self) -> Optional[str]:
        """Get current JWT token."""
        return self.token
    
    def is_token_expired(self) -> bool:
        """Check if current token is expired."""
        if not self.token or not self.token_expires_at:
            return True
        
        # Consider expired if less than 5 minutes remaining
        from datetime import timedelta
        buffer = timedelta(minutes=5)
        return utc_now() >= (self.token_expires_at - buffer)
    
    async def ensure_valid_token(self) -> bool:
        """
        Ensure we have a valid token, refreshing if needed.
        
        Returns:
            True if we have a valid token
        """
        if not self.is_registered:
            return False
        
        if self.is_token_expired():
            logger.info(f"Token expired for {self.cp_id}, re-authenticating...")
            return await self.authenticate()
        
        return True
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for authenticated requests.
        
        Returns:
            Dict with Authorization header if token available
        """
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    async def check_registry_health(self) -> bool:
        """
        Check if EV_Registry is reachable.
        
        Returns:
            True if registry is healthy
        """
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                verify=self.verify_ssl
            ) as client:
                response = await client.get(f"{self.registry_url}/")
                return response.status_code == 200
        except Exception:
            return False
