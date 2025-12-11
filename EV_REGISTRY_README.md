# EV_Registry Service - Release 2

## Overview

The **EV_Registry** is a secure REST API service that manages **Charging Point (CP) registration, deregistration, and authentication** for the EVCharging Network distributed system (Release 2).

### Purpose
- CPs must **register first** before they can authenticate or offer services to EV_Central
- Registration provides secure **credentials and tokens** that CPs use to authenticate
- EV_Registry shares the CP information database with EV_Central
- Provides a **secure channel** (HTTPS/TLS support) for all operations

---

## Architecture

### Components

1. **REST API** (FastAPI)
   - Clean, production-ready endpoints
   - OpenAPI/Swagger documentation
   - JSON request/response bodies
   - Comprehensive error handling

2. **Database Layer** (SQLite)
   - CP registry table with credentials
   - Shared with EV_Central for CP information
   - Persistent storage with indexes

3. **Security Layer**
   - Bcrypt password hashing
   - JWT token generation/validation
   - Certificate fingerprint extraction
   - Secure random credential generation

4. **Configuration** (Pydantic Settings)
   - Environment variable support
   - TLS/SSL configuration
   - Token expiration settings

---

## API Endpoints

### 1. **Register CP**
```http
POST /cp/register
Content-Type: application/json
```

**Request Body:**
```json
{
  "cp_id": "CP-001",
  "location": "Berlin",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "metadata": {
    "power_rating": "22kW",
    "type": "AC"
  }
}
```

**Response (200 OK):**
```json
{
  "cp_id": "CP-001",
  "location": "Berlin",
  "status": "REGISTERED",
  "credentials": "a1b2c3d4e5f6789...",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_expires_at": "2025-12-12T10:30:00Z",
  "registration_date": "2025-12-11T10:30:00Z",
  "message": "CP registered successfully. Store credentials securely - they cannot be retrieved later."
}
```

**Security:**
- Generates 64-character random credentials (returned only once)
- Hashes credentials using bcrypt before storage
- Creates JWT access token valid for configured duration (default 24h)
- Optionally extracts and stores certificate fingerprint
- Validates CP ID format (3-64 alphanumeric, hyphens, underscores)

---

### 2. **Authenticate CP**
```http
POST /cp/authenticate
Content-Type: application/json
```

**Request Body:**
```json
{
  "cp_id": "CP-001",
  "credentials": "a1b2c3d4e5f6789..."
}
```

**Response (200 OK):**
```json
{
  "cp_id": "CP-001",
  "location": "Berlin",
  "status": "REGISTERED",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_expires_at": "2025-12-12T10:30:00Z",
  "last_authenticated": "2025-12-11T10:30:00Z",
  "message": "Authentication successful"
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid credentials or CP not registered
- `403 Forbidden`: CP is deregistered

**Security:**
- Verifies credentials against stored hash
- Returns new JWT token on success
- Updates last_authenticated timestamp
- Never logs sensitive credentials

---

### 3. **Deregister CP**
```http
DELETE /cp/{cp_id}
```

**Response (200 OK):**
```json
{
  "cp_id": "CP-001",
  "status": "DEREGISTERED",
  "message": "CP deregistered successfully",
  "timestamp": "2025-12-11T10:30:00Z"
}
```

**Error Responses:**
- `404 Not Found`: CP not found or already deregistered

**Behavior:**
- Marks CP as DEREGISTERED
- Prevents further authentication
- Historical data is preserved

---

### 4. **Get CP Information**
```http
GET /cp/{cp_id}
```

**Response (200 OK):**
```json
{
  "cp_id": "CP-001",
  "location": "Berlin",
  "status": "REGISTERED",
  "registration_date": "2025-12-11T10:30:00Z",
  "deregistration_date": null,
  "last_authenticated": "2025-12-11T10:35:00Z",
  "has_certificate": true,
  "metadata": {
    "power_rating": "22kW",
    "type": "AC"
  }
}
```

**Security:**
- Does NOT return credentials or hashes
- Public information only

---

### 5. **List All CPs**
```http
GET /cp?status_filter=REGISTERED&limit=100&offset=0
```

**Query Parameters:**
- `status_filter` (optional): `REGISTERED` or `DEREGISTERED`
- `limit` (optional): 1-1000, default 100
- `offset` (optional): Pagination offset, default 0

**Response (200 OK):**
```json
{
  "cps": [
    {
      "cp_id": "CP-001",
      "location": "Berlin",
      "status": "REGISTERED",
      "registration_date": "2025-12-11T10:30:00Z",
      "deregistration_date": null,
      "last_authenticated": "2025-12-11T10:35:00Z",
      "has_certificate": true,
      "metadata": {"power_rating": "22kW"}
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

---

### 6. **Health Check**
```http
GET /
```

**Response (200 OK):**
```json
{
  "service": "EV Registry",
  "status": "operational",
  "version": "2.0.0",
  "timestamp": "2025-12-11T10:30:00Z"
}
```

---

## Security Features

### 1. **Credential Management**
- **Generation**: 64-character secure random hex strings
- **Hashing**: Bcrypt with automatic salt
- **Verification**: Constant-time comparison
- **Storage**: Only hashes stored, never plain text

### 2. **JWT Tokens**
- **Algorithm**: HS256 (HMAC-SHA256)
- **Claims**: `sub` (cp_id), `type`, `iat`, `exp`, `nbf`, `location`
- **Expiration**: Configurable (default 24 hours)
- **Validation**: Signature, expiration, type verification

### 3. **Certificate Support**
- Extract SHA-256 fingerprint from PEM certificates
- Store fingerprint for future certificate-based authentication
- Optional validation (configured via `REGISTRY_REQUIRE_CERTIFICATE`)

### 4. **TLS/HTTPS**
- Configurable SSL/TLS support
- Certificate and key file configuration
- Production-ready for secure communication

### 5. **Input Validation**
- CP ID: 3-64 characters, alphanumeric + hyphens/underscores
- Location: 2-256 characters
- All inputs validated with Pydantic models
- SQL injection prevention via parameterized queries

---

## Configuration

### Environment Variables

```bash
# API Configuration
REGISTRY_API_PORT=8080
REGISTRY_DB_PATH=/data/ev_registry.db
REGISTRY_LOG_LEVEL=INFO

# Security
REGISTRY_SECRET_KEY=your-secret-key-change-in-production
REGISTRY_TOKEN_EXPIRATION_HOURS=24
REGISTRY_REQUIRE_CERTIFICATE=false

# TLS/SSL (Optional)
REGISTRY_TLS_ENABLED=false
REGISTRY_TLS_CERT_FILE=/path/to/cert.pem
REGISTRY_TLS_KEY_FILE=/path/to/key.pem

# Admin API (Optional)
REGISTRY_ADMIN_API_KEY=admin-key-for-management-endpoints
REGISTRY_API_KEY_HEADER=X-Registry-API-Key
```

### Configuration File (.env)
```env
REGISTRY_API_PORT=8080
REGISTRY_DB_PATH=ev_charging.db
REGISTRY_LOG_LEVEL=INFO
REGISTRY_SECRET_KEY=change-this-secret-key-in-production
REGISTRY_TOKEN_EXPIRATION_HOURS=24
```

---

## Database Schema

### `cp_registry` Table
```sql
CREATE TABLE cp_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cp_id TEXT NOT NULL UNIQUE,
    location TEXT NOT NULL,
    credentials_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'REGISTERED',
    registration_date TEXT NOT NULL,
    deregistration_date TEXT,
    last_authenticated TEXT,
    certificate_fingerprint TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

**Indexes:**
- `idx_cp_registry_cp_id` on `cp_id`
- `idx_cp_registry_status` on `status`

---

## Docker Deployment

### Build Image
```bash
docker build -f docker/Dockerfile.registry -t ev-registry:latest .
```

### Run Standalone
```bash
docker run -d \
  --name ev-registry \
  -p 8080:8080 \
  -e REGISTRY_SECRET_KEY=your-secret-key \
  -v registry-data:/data \
  ev-registry:latest
```

### Docker Compose
The service is integrated into `docker-compose.yml`:
```bash
docker compose up ev-registry
```

Access API documentation: http://localhost:8080/docs

---

## Integration with Existing System

### 1. **CP Monitor (EV_CP_M) Integration**

Before connecting to EV_Central, CP_M should register with EV_Registry:

```python
import httpx

# Register CP
async def register_cp():
    registration = {
        "cp_id": "CP-001",
        "location": "Berlin"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://ev-registry:8080/cp/register",
            json=registration,
            verify=True  # Verify TLS certificate
        )
        
        if response.status_code == 200:
            data = response.json()
            credentials = data["credentials"]  # Store securely!
            token = data["token"]
            # Use token for EV_Central authentication
```

### 2. **EV_Central Integration**

EV_Central can query CP information from shared database:

```python
from evcharging.common.database import CPRegistryDB

db = CPRegistryDB("ev_charging.db")

# Check if CP is registered
cp_info = db.get_cp("CP-001")
if cp_info and cp_info['status'] == 'REGISTERED':
    # Allow CP to connect
    pass
else:
    # Reject connection
    pass
```

### 3. **Token Validation**

Services can validate JWT tokens:

```python
from evcharging.common.security import SecurityManager

security_mgr = SecurityManager(secret_key="your-secret")
claims = security_mgr.verify_access_token(token)

if claims:
    cp_id = claims['sub']
    # Token is valid
else:
    # Token is invalid or expired
```

---

## Testing

### Manual Testing with curl

**Register a CP:**
```bash
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-TEST-001",
    "location": "Berlin"
  }'
```

**Authenticate:**
```bash
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-TEST-001",
    "credentials": "<credentials-from-registration>"
  }'
```

**Get CP Info:**
```bash
curl http://localhost:8080/cp/CP-TEST-001
```

**List all CPs:**
```bash
curl http://localhost:8080/cp
```

**Deregister:**
```bash
curl -X DELETE http://localhost:8080/cp/CP-TEST-001
```

### Automated Test Script

See `test_registry.sh` for comprehensive testing.

---

## Production Deployment Checklist

- [ ] Change `REGISTRY_SECRET_KEY` to a strong random value
- [ ] Enable TLS/HTTPS with valid certificates
- [ ] Configure `REGISTRY_REQUIRE_CERTIFICATE=true` for certificate-based auth
- [ ] Set appropriate `REGISTRY_TOKEN_EXPIRATION_HOURS`
- [ ] Use production database path with proper permissions
- [ ] Configure firewall to restrict API access
- [ ] Enable rate limiting (consider nginx/traefik in front)
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Backup database regularly

---

## Logging

All operations are logged with structured logging:

```
2025-12-11 10:30:00 | INFO     | ev_registry:register_cp | CP registered: CP-001 at Berlin (new=True, cert=True)
2025-12-11 10:35:00 | INFO     | ev_registry:authenticate_cp | CP authenticated successfully: CP-001
2025-12-11 10:40:00 | WARNING  | ev_registry:authenticate_cp | Authentication failed: Invalid credentials for CP-002
```

---

## Error Handling

All errors return consistent JSON structure:

```json
{
  "error": "Invalid credentials or CP not registered",
  "detail": null,
  "timestamp": "2025-12-11T10:30:00Z"
}
```

**HTTP Status Codes:**
- `200 OK`: Successful operation
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: CP is deregistered
- `404 Not Found`: CP not found
- `500 Internal Server Error`: Server error

---

## API Documentation

Interactive API documentation available at:
- **Swagger UI**: http://localhost:8080/docs
- **ReDoc**: http://localhost:8080/redoc

---

## Compliance with Specification

✅ **Registration via REST API** (GET, POST, PUT, DELETE)  
✅ **Secure channel support** (HTTPS/TLS/SSL/RSA)  
✅ **Certificate-based identification** (optional)  
✅ **Credentials generation and storage**  
✅ **Authentication mechanism**  
✅ **Shared database with EV_Central**  
✅ **CP must register before authentication**  
✅ **Production-ready security patterns**

---

## License

Part of EVCharging Network - Release 2
