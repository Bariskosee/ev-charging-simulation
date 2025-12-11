# EV_Registry Integration Guide

## Overview

This guide shows how to integrate the new **EV_Registry** service (Release 2) with existing EVCharging system components (Release 1).

---

## Integration Architecture

```
┌─────────────┐
│   EV_CP_M   │ ──────① Register────────┐
│  (Monitor)  │                          │
└─────────────┘                          ▼
       │                           ┌──────────────┐
       │                           │ EV_Registry  │
       │                           │  (REST API)  │
       │                           └──────────────┘
       │                                  │
       │                                  │ Shared DB
       │                                  ▼
       │                           ┌──────────────┐
       │──────② Connect──────────▶ │  EV_Central  │
       │                           └──────────────┘
       │
       ▼
┌─────────────┐
│   EV_CP_E   │
│  (Engine)   │
└─────────────┘
```

**Flow**:
1. CP Monitor registers with EV_Registry (gets credentials + token)
2. CP Monitor connects to EV_Central (uses token for auth)
3. EV_Central validates CP is registered via shared database

---

## Step 1: Update EV_CP_M (CP Monitor)

### 1.1 Add Registry Client

Create `evcharging/common/registry_client.py`:

```python
"""Client for EV_Registry API."""

import httpx
from typing import Optional, Dict
from loguru import logger


class RegistryClient:
    """Client for CP registration and authentication."""
    
    def __init__(self, registry_url: str):
        self.registry_url = registry_url
        self.cp_id: Optional[str] = None
        self.credentials: Optional[str] = None
        self.token: Optional[str] = None
        self.location: Optional[str] = None
    
    async def register(
        self,
        cp_id: str,
        location: str,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Register this CP with EV_Registry.
        
        Args:
            cp_id: Charging point identifier
            location: CP location (city/address)
            metadata: Optional metadata dict
            
        Returns:
            True if registration successful
        """
        registration_data = {
            "cp_id": cp_id,
            "location": location
        }
        
        if metadata:
            registration_data["metadata"] = metadata
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.registry_url}/cp/register",
                    json=registration_data
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.cp_id = cp_id
                    self.location = location
                    self.credentials = data["credentials"]
                    self.token = data["token"]
                    
                    logger.info(
                        f"CP {cp_id} registered successfully with EV_Registry"
                    )
                    return True
                else:
                    logger.error(
                        f"Registration failed: {response.status_code} - {response.text}"
                    )
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
            async with httpx.AsyncClient(timeout=10.0) as client:
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
                    logger.info(f"CP {self.cp_id} authenticated successfully")
                    return True
                else:
                    logger.error(
                        f"Authentication failed: {response.status_code} - {response.text}"
                    )
                    return False
        
        except Exception as e:
            logger.error(f"Error authenticating with EV_Registry: {e}")
            return False
    
    def get_token(self) -> Optional[str]:
        """Get current JWT token."""
        return self.token
```

### 1.2 Update CPMonitorConfig

In `evcharging/common/config.py`, add to `CPMonitorConfig`:

```python
class CPMonitorConfig(BaseSettings):
    """Configuration for CP Monitor service."""
    
    cp_id: str = Field(..., description="Charging point ID")
    location: str = Field(default="Unknown", description="CP location")
    cp_e_host: str = Field(default="localhost", description="CP Engine host")
    cp_e_port: int = Field(default=8001, description="CP Engine port")
    central_host: str = Field(default="localhost", description="Central host")
    central_port: int = Field(default=8000, description="Central HTTP port")
    health_interval: float = Field(default=1.0, description="Health check interval (seconds)")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # NEW: EV_Registry settings
    registry_url: str = Field(
        default="http://localhost:8080",
        description="EV_Registry API URL"
    )
    registry_enabled: bool = Field(
        default=True,
        description="Enable registration with EV_Registry"
    )
    
    model_config = SettingsConfigDict(
        env_prefix="CP_MONITOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
```

### 1.3 Modify CPMonitor Startup

In `evcharging/apps/ev_cp_m/main.py`:

```python
from evcharging.common.registry_client import RegistryClient


class CPMonitor:
    """Monitor for Charging Point health and connectivity."""
    
    def __init__(self, config: CPMonitorConfig):
        self.config = config
        self.cp_id = config.cp_id
        self.is_healthy = True
        self.fault_simulated = False
        self._running = False
        
        # NEW: Initialize registry client
        self.registry_client = RegistryClient(config.registry_url)
    
    async def start(self):
        """Initialize and start the CP Monitor."""
        logger.info(f"Starting CP Monitor for {self.cp_id}")
        
        # NEW: Register with EV_Registry if enabled
        if self.config.registry_enabled:
            await self._register_with_registry()
        
        # Then register with Central (existing flow)
        await self.register_with_central()
        
        self._running = True
        logger.info(f"CP Monitor {self.cp_id} started successfully")
    
    async def _register_with_registry(self):
        """Register with EV_Registry service."""
        logger.info(f"Registering {self.cp_id} with EV_Registry...")
        
        metadata = {
            "cp_e_host": self.config.cp_e_host,
            "cp_e_port": self.config.cp_e_port
        }
        
        success = await self.registry_client.register(
            cp_id=self.cp_id,
            location=self.config.location,
            metadata=metadata
        )
        
        if success:
            logger.info(
                f"✓ CP {self.cp_id} registered with EV_Registry"
            )
            # Store credentials securely (in production, use vault/secrets)
            # For now, stored in memory in registry_client
        else:
            logger.error(
                f"✗ Failed to register {self.cp_id} with EV_Registry"
            )
            # Decide: continue anyway or abort?
    
    async def register_with_central(self):
        """Register with Central (existing method - now includes token)."""
        registration = CPRegistration(
            cp_id=self.cp_id,
            cp_e_host=self.config.cp_e_host,
            cp_e_port=self.config.cp_e_port
        )
        
        central_url = f"http://{self.config.central_host}:{self.config.central_port}"
        
        max_retries = 10
        retry_delay = 2.0
        
        for attempt in range(1, max_retries + 1):
            try:
                # NEW: Include JWT token if registered
                headers = {}
                if self.registry_client.token:
                    headers["Authorization"] = f"Bearer {self.registry_client.token}"
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{central_url}/cp/register",
                        json=registration.model_dump(mode='json'),
                        headers=headers,
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        logger.info(
                            f"CP {self.cp_id} registered with Central (attempt {attempt})"
                        )
                        return
                    else:
                        logger.warning(
                            f"Failed to register CP (attempt {attempt}/{max_retries}): "
                            f"{response.status_code} {response.text}"
                        )
            
            except Exception as e:
                logger.warning(
                    f"Error registering with Central (attempt {attempt}/{max_retries}): {e}"
                )
            
            if attempt < max_retries:
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 1.5, 10.0)
            else:
                logger.error(
                    f"Failed to register CP {self.cp_id} after {max_retries} attempts"
                )
```

---

## Step 2: Update EV_Central

### 2.1 Validate CP Registration

In `evcharging/apps/ev_central/main.py`:

```python
from evcharging.common.database import CPRegistryDB


class EVCentralController:
    """Main controller managing all charging points and driver requests."""
    
    def __init__(self, config: CentralConfig):
        self.config = config
        # ... existing initialization ...
        
        # NEW: Initialize registry database
        self.registry_db = CPRegistryDB(config.db_url or "ev_charging.db")
    
    def register_cp(self, registration: CPRegistration) -> bool:
        """
        Register a charging point with Central.
        
        NEW: Validates CP is registered in EV_Registry first.
        """
        cp_id = registration.cp_id
        
        # NEW: Check if CP is registered in registry
        cp_info = self.registry_db.get_cp(cp_id)
        
        if not cp_info:
            logger.warning(
                f"CP {cp_id} attempted to register but not found in EV_Registry"
            )
            return False
        
        if cp_info['status'] != 'REGISTERED':
            logger.warning(
                f"CP {cp_id} is {cp_info['status']} in EV_Registry - rejecting"
            )
            return False
        
        # CP is valid - proceed with existing registration logic
        logger.info(
            f"CP {cp_id} validated via EV_Registry (location: {cp_info['location']})"
        )
        
        if cp_id not in self.charging_points:
            self.charging_points[cp_id] = ChargingPoint(
                cp_id=cp_id,
                cp_e_host=registration.cp_e_host,
                cp_e_port=registration.cp_e_port
            )
            logger.info(f"Registered new CP: {cp_id}")
        else:
            # Update existing CP
            cp = self.charging_points[cp_id]
            cp.cp_e_host = registration.cp_e_host
            cp.cp_e_port = registration.cp_e_port
            logger.info(f"Updated existing CP: {cp_id}")
        
        return True
```

### 2.2 Optional: Token Validation

For enhanced security, validate JWT tokens:

```python
from evcharging.common.security import create_security_manager


class EVCentralController:
    """Main controller managing all charging points and driver requests."""
    
    def __init__(self, config: CentralConfig):
        self.config = config
        # ... existing ...
        
        # NEW: Security manager for token validation
        self.security_mgr = create_security_manager(
            secret_key=config.registry_secret_key,
            token_expiration_hours=24
        )
    
    def validate_cp_token(self, token: str) -> Optional[str]:
        """
        Validate JWT token from CP.
        
        Returns:
            CP ID if valid, None otherwise
        """
        claims = self.security_mgr.verify_access_token(token)
        if claims:
            return claims.get('sub')  # 'sub' contains cp_id
        return None
```

In `evcharging/apps/ev_central/dashboard.py`, add token validation:

```python
from fastapi import Header, HTTPException


@app.post("/cp/register")
async def register_cp(
    registration: CPRegistration,
    authorization: Optional[str] = Header(None)
):
    """Register CP - now validates token if provided."""
    
    # NEW: Validate token if present
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]  # Remove "Bearer " prefix
        cp_id_from_token = controller.validate_cp_token(token)
        
        if not cp_id_from_token:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if cp_id_from_token != registration.cp_id:
            raise HTTPException(
                status_code=403,
                detail="Token cp_id does not match registration"
            )
    
    # Proceed with registration
    success = controller.register_cp(registration)
    
    if success:
        return {"status": "ok", "message": f"CP {registration.cp_id} registered"}
    else:
        raise HTTPException(
            status_code=403,
            detail="CP not registered in EV_Registry or is deregistered"
        )
```

---

## Step 3: Update Docker Compose

### 3.1 Add Environment Variables

In `docker-compose.yml`, update CP Monitor services:

```yaml
ev-cp-m-1:
  build:
    context: .
    dockerfile: docker/Dockerfile.cp_m
  container_name: ev-cp-m-1
  environment:
    SERVICE_TYPE: cp_monitor
    CP_MONITOR_CP_ID: CP-001
    CP_MONITOR_LOCATION: "Berlin"  # NEW
    CP_MONITOR_CP_E_HOST: ev-cp-e-1
    CP_MONITOR_CP_E_PORT: 8001
    CP_MONITOR_CENTRAL_HOST: ev-central
    CP_MONITOR_CENTRAL_PORT: 8000
    CP_MONITOR_HEALTH_INTERVAL: 1.0
    CP_MONITOR_LOG_LEVEL: INFO
    CP_MONITOR_REGISTRY_URL: "http://ev-registry:8080"  # NEW
    CP_MONITOR_REGISTRY_ENABLED: "true"  # NEW
  depends_on:
    ev-registry:  # NEW
      condition: service_healthy
    ev-central:
      condition: service_started
  networks:
    - evcharging-network
```

Repeat for all CP monitors (ev-cp-m-2 through ev-cp-m-10).

### 3.2 Update EV_Central Dependencies

```yaml
ev-central:
  build:
    context: .
    dockerfile: docker/Dockerfile.central
  container_name: ev-central
  environment:
    # ... existing ...
    CENTRAL_REGISTRY_SECRET_KEY: ${REGISTRY_SECRET_KEY:-dev-secret}  # NEW
  depends_on:
    kafka:
      condition: service_healthy
    ev-registry:  # NEW
      condition: service_healthy
  networks:
    - evcharging-network
```

---

## Step 4: Testing the Integration

### 4.1 Start Services

```bash
# Build with new changes
docker compose build

# Start all services
docker compose up -d

# Check logs
docker compose logs -f ev-registry
docker compose logs -f ev-cp-m-1
docker compose logs -f ev-central
```

### 4.2 Verify Registration Flow

Expected log sequence:

**EV_Registry**:
```
2025-12-11 10:00:00 | INFO | CP registered: CP-001 at Berlin (new=True, cert=False)
```

**CP Monitor (ev-cp-m-1)**:
```
2025-12-11 10:00:01 | INFO | Registering CP-001 with EV_Registry...
2025-12-11 10:00:02 | INFO | ✓ CP CP-001 registered with EV_Registry
2025-12-11 10:00:03 | INFO | CP CP-001 registered with Central successfully
```

**EV_Central**:
```
2025-12-11 10:00:03 | INFO | CP CP-001 validated via EV_Registry (location: Berlin)
2025-12-11 10:00:03 | INFO | Registered new CP: CP-001
```

### 4.3 Test Registry API

```bash
# List all registered CPs
curl http://localhost:8080/cp

# Get specific CP
curl http://localhost:8080/cp/CP-001

# Should show REGISTERED status and last_authenticated timestamp
```

### 4.4 Test Rejection of Unregistered CP

Manually try to register a CP that's not in registry:

```bash
curl -X POST http://localhost:8000/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-FAKE",
    "cp_e_host": "fake",
    "cp_e_port": 9999
  }'

# Expected: 403 Forbidden with message about not being in EV_Registry
```

---

## Step 5: Production Hardening

### 5.1 Secure Credential Storage

Replace in-memory storage with secure vault:

```python
# In CPMonitor
import keyring

async def _register_with_registry(self):
    success = await self.registry_client.register(...)
    
    if success:
        # Store credentials securely
        keyring.set_password(
            "ev-registry",
            f"cp-{self.cp_id}",
            self.registry_client.credentials
        )
```

### 5.2 Enable TLS

```yaml
# docker-compose.yml
ev-registry:
  environment:
    REGISTRY_TLS_ENABLED: "true"
    REGISTRY_TLS_CERT_FILE: "/certs/registry-cert.pem"
    REGISTRY_TLS_KEY_FILE: "/certs/registry-key.pem"
  volumes:
    - ./certs:/certs:ro
```

Update CP Monitor URLs:
```yaml
CP_MONITOR_REGISTRY_URL: "https://ev-registry:8080"
```

### 5.3 Change Secret Keys

```bash
# Generate strong secret
openssl rand -hex 32

# Set in environment
export REGISTRY_SECRET_KEY="your-generated-secret"
```

---

## Migration Checklist

- [ ] Add `registry_client.py` to common module
- [ ] Update `CPMonitorConfig` with registry settings
- [ ] Modify `CPMonitor.start()` to register with registry
- [ ] Update `EVCentralController` to validate CP registration
- [ ] Add token validation to Central dashboard (optional)
- [ ] Update docker-compose.yml with new environment variables
- [ ] Add ev-registry dependency to ev-cp-m services
- [ ] Test registration flow end-to-end
- [ ] Verify rejection of unregistered CPs
- [ ] Enable TLS for production
- [ ] Implement secure credential storage
- [ ] Update documentation

---

## Backward Compatibility

The integration is designed to be **backward compatible**:

- Set `CP_MONITOR_REGISTRY_ENABLED=false` to disable registry integration
- System will work as before (Release 1 mode)
- Enables gradual rollout in existing deployments

---

## Troubleshooting

### CP Monitor fails to start
- Check if ev-registry is healthy: `docker compose ps ev-registry`
- Verify registry URL is correct: `echo $CP_MONITOR_REGISTRY_URL`
- Check registry logs: `docker compose logs ev-registry`

### Central rejects registered CP
- Verify CP is in registry: `curl http://localhost:8080/cp/CP-001`
- Check status is REGISTERED
- Verify shared database path matches
- Check Central has registry_db initialized

### Token validation fails
- Verify secret keys match between Registry and Central
- Check token hasn't expired (default 24h)
- Validate token format (should be Bearer <token>)

---

## Next Steps

1. **Deploy**: Follow this guide to integrate
2. **Test**: Use `test_registry.sh` to verify
3. **Monitor**: Watch logs for successful registration flow
4. **Harden**: Enable TLS and secure credential storage
5. **Document**: Update your deployment docs with new steps

---

## Support

For questions or issues:
- Check logs: `docker compose logs -f <service>`
- Review API docs: http://localhost:8080/docs
- See full documentation: `EV_REGISTRY_README.md`
