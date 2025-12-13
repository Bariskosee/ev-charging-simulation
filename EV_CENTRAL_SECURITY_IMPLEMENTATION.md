# EV_Central Security Extensions - Implementation Guide

## Overview

This document describes the **Release 2 Security Extensions** implemented for EV_Central in the EVCharging Network. These extensions add comprehensive security features while preserving all existing functionality from Release 1.

---

## Architecture

### Security Components

```
┌─────────────────────────────────────────────────────────────┐
│                      EV_Central                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │         EVCentralController                        │     │
│  │  - Manages CPs and charging sessions              │     │
│  │  - Integrates CPSecurityService                   │     │
│  │  - Enforces authentication & authorization        │     │
│  └────────────────────────────────────────────────────┘     │
│                          │                                   │
│  ┌────────────────────────────────────────────────────┐     │
│  │         CPSecurityService                          │     │
│  │  - CP authentication (credentials & tokens)        │     │
│  │  - Encryption key management (generate/revoke)     │     │
│  │  - Status enforcement (ACTIVE/OUT_OF_SERVICE/      │     │
│  │    REVOKED)                                        │     │
│  │  - Payload encryption/decryption                   │     │
│  └────────────────────────────────────────────────────┘     │
│           │                    │                             │
│  ┌────────────────┐   ┌──────────────────┐                 │
│  │  CPSecurityDB  │   │  CPRegistryDB    │                 │
│  │  - Key storage │   │  - Credentials   │                 │
│  │  - Status mgmt │   │  - CP registry   │                 │
│  └────────────────┘   └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    EV_Registry                               │
│  - Issues credentials to CPs during registration            │
│  - Root of trust for authentication                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Features

### 1. CP Authentication

**Implementation:** `evcharging/common/cp_security.py:CPSecurityService.authenticate_cp()`

EV_Central authenticates every CP using credentials issued by EV_Registry:

- **Credential Verification:** Validates secret credentials against hashed values stored in `cp_registry` table
- **Token Generation:** Issues JWT tokens for authenticated sessions
- **Status Validation:** Checks CP registration status (ACTIVE, OUT_OF_SERVICE, REVOKED)
- **Audit Logging:** Records all authentication attempts (success and failure)

**Authentication Flow:**
```
1. CP provides cp_id + credentials
2. EV_Central queries CPRegistryDB for credentials_hash
3. Verifies credentials using bcrypt
4. Checks security status in CPSecurityDB
5. Generates JWT token if authorized
6. Records authentication timestamp
```

**Code Example:**
```python
# Authenticate CP with credentials
result = controller.cp_security.authenticate_cp(cp_id, credentials)
if result.is_authorized():
    # CP is ACTIVE and authenticated
    token = result.token
else:
    # Authentication failed or CP is REVOKED/OUT_OF_SERVICE
    reason = result.reason
```

---

### 2. Per-CP Unique Symmetric Encryption Keys

**Implementation:** `evcharging/common/cp_security.py:CPEncryptionService`

Every CP has a unique 256-bit AES encryption key:

- **Key Generation:** Cryptographically secure random keys using `secrets.token_bytes(32)`
- **Key Storage:** Keys are hashed (SHA-256) before storage; plaintext keys exist only in memory
- **Key Association:** One-to-one mapping between CP and encryption key
- **Encryption Algorithm:** AES-GCM (authenticated encryption with associated data)

**Key Lifecycle:**
```
Generation → Active Use → Rotation → Revocation
     ↓            ↓           ↓          ↓
  Stored in   Cached in   Old key    Removed from
    DB as     memory as  invalidated  cache & DB
  SHA-256     raw bytes    immediately
   hash
```

**Database Schema:**
```sql
CREATE TABLE cp_encryption_keys (
    id INTEGER PRIMARY KEY,
    cp_id TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,           -- SHA-256 hash (never plaintext)
    key_created_at TEXT NOT NULL,
    key_rotated_at TEXT,
    key_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE'  -- ACTIVE or REVOKED
);
```

---

### 3. Key Revoke & Reset Mechanism

**Implementation:** `evcharging/common/cp_security.py:CPSecurityService`

**Key Revocation:**
- Immediately invalidates the current key
- Removes key from in-memory cache
- Marks key as REVOKED in database
- All subsequent encrypted requests fail

**Key Reset (Rotation):**
- Revokes old key
- Generates new cryptographically secure key
- Increments key version
- Updates database with new key hash

**Code Example:**
```python
# Revoke a CP's key
controller.cp_security.revoke_key_for_cp(cp_id)

# Reset (rotate) a CP's key
controller.cp_security.reset_key_for_cp(cp_id)
```

---

### 4. CP Status Management

**Implementation:** `evcharging/common/database.py:CPSecurityDB`

Three distinct security statuses:

| Status | Description | Operations Allowed |
|--------|-------------|-------------------|
| **ACTIVE** | Normal operation | All operations (charging, telemetry, commands) |
| **OUT_OF_SERVICE** | Temporary maintenance | Authentication succeeds but no charging operations |
| **REVOKED** | Permanently disabled | All operations fail; complete access denial |

**Status Transitions:**
```
ACTIVE ←→ OUT_OF_SERVICE
   ↓
REVOKED (permanent - no recovery)
```

**Enforcement Points:**
- CP registration
- Driver request handling
- Status updates
- Command processing

**Code Example:**
```python
# Mark CP as out of service
controller.set_cp_out_of_service(cp_id, reason="Scheduled maintenance")

# Restore CP to active
controller.restore_cp_to_active(cp_id)

# Revoke CP (CRITICAL - permanent)
controller.revoke_cp_access(cp_id, reason="Security violation detected")
```

---

### 5. Encrypted Central ↔ CP Communication

**Implementation:** `evcharging/common/cp_security.py:CPEncryptionService`

**Encryption Details:**
- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key Size:** 256 bits (32 bytes)
- **Nonce Size:** 96 bits (12 bytes, randomly generated per message)
- **Authentication:** Built-in authentication tag (AEAD)
- **Encoding:** Base64 for transport

**Payload Format:**
```
Base64( nonce[12 bytes] || ciphertext || auth_tag[16 bytes] )
```

**Encryption Process:**
```python
# Encrypt payload for CP
payload = {"command": "START_SUPPLY", "session_id": "sess-123"}
encrypted = controller.cp_security.encrypt_for_cp(cp_id, payload)

# Decrypt payload from CP
decrypted = controller.cp_security.decrypt_from_cp(cp_id, encrypted_payload)
```

**Security Properties:**
- **Confidentiality:** Payload content protected by AES-256
- **Integrity:** Authentication tag prevents tampering
- **Authenticity:** Each CP has unique key; messages cannot be forged
- **Replay Protection:** Nonce ensures uniqueness (application-level timestamp checks recommended)

---

### 6. Integration with EV_Registry

**Root of Trust:** EV_Registry issues credentials during CP registration

**Shared Database Model:**
```
EV_Registry                      EV_Central
     │                               │
     ├─ Writes to cp_registry       │
     │  - cp_id                      │
     │  - credentials_hash ──────────┼─ Reads for authentication
     │  - location                   │
     │  - status                     │
     │                               │
     │                               ├─ Writes to cp_security_status
     │                               │  - registration_status
     │                               │  - last_authenticated_at
     │                               │
     │                               ├─ Writes to cp_encryption_keys
     │                               │  - key_hash
     │                               │  - key_version
     │                               │  - status
```

**No Re-Registration:**
- EV_Central does NOT register CPs
- EV_Central relies on EV_Registry-issued credentials
- Credentials are NEVER logged or exposed

---

## Database Schema

### Security Tables

```sql
-- CP encryption keys
CREATE TABLE cp_encryption_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cp_id TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    key_created_at TEXT NOT NULL,
    key_rotated_at TEXT,
    key_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CP security status
CREATE TABLE cp_security_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cp_id TEXT NOT NULL UNIQUE,
    registration_status TEXT NOT NULL DEFAULT 'ACTIVE',
    last_authenticated_at TEXT,
    auth_failure_count INTEGER DEFAULT 0,
    last_auth_failure_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT,
    out_of_service_at TEXT,
    out_of_service_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Shared with EV_Registry
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

---

## REST API Endpoints

### Security API (Port 8000 by default)

**Authentication:**
- `POST /auth/credentials` - Authenticate with credentials
- `POST /auth/token` - Authenticate with JWT token

**Key Management (Admin Only):**
- `POST /keys/generate` - Generate encryption key
- `POST /keys/revoke` - Revoke encryption key
- `POST /keys/reset` - Reset (rotate) encryption key

**Status Management (Admin Only):**
- `POST /status/revoke` - Revoke CP access (permanent)
- `POST /status/out-of-service` - Mark CP as out of service
- `POST /status/restore` - Restore CP to active

**Monitoring:**
- `GET /security/status/{cp_id}` - Get CP security status
- `GET /security/status` - Get all CP security statuses
- `GET /health` - Health check

**Admin Authentication:**
All admin endpoints require `X-Admin-Key` header.

---

## Enhanced ChargingPoint Model

```python
class ChargingPoint:
    # Existing attributes
    cp_id: str
    state: CPState
    current_driver: str | None
    current_session: str | None
    # ... (Release 1 attributes)
    
    # NEW: Security attributes
    is_authenticated: bool            # CP has valid authentication
    auth_token: str | None            # Current JWT token
    security_status: CPSecurityStatus # ACTIVE, OUT_OF_SERVICE, REVOKED
    last_auth_time: datetime | None   # Last successful authentication
    has_encryption_key: bool          # Encryption key exists
    
    def is_security_authorized(self) -> bool:
        """Check if CP is authorized from security perspective."""
        return (
            self.is_authenticated and 
            self.security_status == CPSecurityStatus.ACTIVE and
            self.has_encryption_key
        )
```

---

## Usage Examples

### Example 1: CP Authentication Flow

```python
# CP provides credentials (from EV_Registry registration)
cp_id = "CP-001"
credentials = "a1b2c3d4e5f6..."  # Secret from registration

# Authenticate
auth_result = controller.cp_security.authenticate_cp(cp_id, credentials)

if auth_result.is_authorized():
    print(f"CP {cp_id} authenticated successfully")
    token = auth_result.token  # Use for subsequent requests
else:
    print(f"Authentication failed: {auth_result.reason}")
    print(f"Status: {auth_result.status.value}")
```

### Example 2: Handling Driver Requests with Security

```python
async def handle_driver_request(self, request: DriverRequest):
    cp = self.charging_points.get(request.cp_id)
    
    # Security check
    if not cp.is_security_authorized():
        await self._send_driver_update(
            request,
            MessageStatus.DENIED,
            f"CP not authorized (status: {cp.security_status.value})"
        )
        return
    
    # Proceed with charging if security passes
    # ... (existing logic)
```

### Example 3: Key Rotation

```python
# Regular key rotation (e.g., every 30 days)
for cp_id in controller.charging_points.keys():
    key_info = controller.security_db.get_key_info(cp_id)
    if key_age_days(key_info) > 30:
        controller.cp_security.reset_key_for_cp(cp_id)
        logger.info(f"Rotated encryption key for CP {cp_id}")
```

### Example 4: Emergency CP Revocation

```python
# Detect security violation
if security_violation_detected(cp_id):
    # Immediately revoke CP access
    controller.revoke_cp_access(
        cp_id,
        reason="Security violation: unauthorized access attempt detected"
    )
    
    # CP is now REVOKED
    # - All operations fail
    # - Encryption key revoked
    # - Active sessions terminated
```

---

## Error Handling

### HTTP Status Codes

- **200 OK** - Operation successful
- **400 Bad Request** - Invalid request payload (e.g., malformed encrypted data)
- **401 Unauthorized** - Authentication failed (invalid credentials or token)
- **403 Forbidden** - CP is REVOKED or OUT_OF_SERVICE
- **404 Not Found** - CP not found
- **500 Internal Server Error** - Unexpected failure

### Security-Specific Errors

```python
# Authentication failure
if not auth_result.success:
    # Log failure
    # Increment auth_failure_count
    # Return 401 Unauthorized

# REVOKED CP
if cp.security_status == CPSecurityStatus.REVOKED:
    # Log attempt
    # Return 403 Forbidden with reason

# OUT_OF_SERVICE CP
if cp.security_status == CPSecurityStatus.OUT_OF_SERVICE:
    # Allow authentication but deny operations
    # Return 403 Forbidden with maintenance message

# Encryption failure
try:
    decrypted = decrypt_from_cp(cp_id, encrypted_payload)
except ValueError:
    # Invalid key or tampered data
    # Return 400 Bad Request
```

---

## Security Best Practices

### Key Management

1. **Never log encryption keys or credentials** (plaintext or hashed)
2. **Rotate keys regularly** (recommended: every 30-90 days)
3. **Use HSM or KMS** in production for key storage
4. **Revoke keys immediately** upon security incident

### Authentication

1. **Use tokens for API calls** (not credentials)
2. **Set token expiration** (default: 24 hours)
3. **Implement rate limiting** for authentication endpoints
4. **Monitor auth failure counts** for brute-force detection

### Status Management

1. **OUT_OF_SERVICE for temporary issues** (maintenance, testing)
2. **REVOKED for permanent security violations** (no recovery)
3. **Audit all status changes** with timestamps and reasons
4. **Notify administrators** of revocation events

### Encryption

1. **Always use HTTPS** (TLS) for transport security
2. **Validate nonces** to prevent replay attacks (application-level)
3. **Handle decryption failures** as potential attacks
4. **Use separate keys per CP** (never share keys)

---

## Configuration

### Environment Variables

```bash
# Security secret key (32+ characters)
export EV_SECURITY_SECRET="your-production-secret-key-minimum-32-chars!!!"

# Admin API key
export EV_ADMIN_KEY="your-admin-key-change-in-production"

# Database path
export EV_DB_PATH="/path/to/ev_charging.db"

# Token expiration (hours)
export EV_TOKEN_EXPIRATION_HOURS=24
```

### Startup Configuration

```python
# Initialize EV_Central with security
config = CentralConfig(
    listen_port=7000,
    http_port=8000,
    kafka_bootstrap="localhost:9092",
    db_url="ev_charging.db",
    log_level="INFO"
)

controller = EVCentralController(config)
await controller.start()
```

---

## Testing

### Unit Tests

```python
# Test authentication
def test_cp_authentication():
    result = security_service.authenticate_cp(cp_id, valid_credentials)
    assert result.success
    assert result.is_authorized()
    assert result.token is not None

# Test key management
def test_key_rotation():
    security_service.generate_key_for_cp(cp_id)
    old_key_hash = security_db.get_encryption_key_hash(cp_id)
    
    security_service.reset_key_for_cp(cp_id)
    new_key_hash = security_db.get_encryption_key_hash(cp_id)
    
    assert old_key_hash != new_key_hash

# Test encryption
def test_payload_encryption():
    payload = {"command": "TEST", "data": "secret"}
    encrypted = security_service.encrypt_for_cp(cp_id, payload)
    decrypted = security_service.decrypt_from_cp(cp_id, encrypted)
    assert decrypted == payload
```

### Integration Tests

```python
# Test driver request with security
async def test_driver_request_security():
    # Unauthenticated CP
    cp.is_authenticated = False
    response = await handle_driver_request(request)
    assert response.status == MessageStatus.DENIED
    
    # Authenticated CP
    cp.is_authenticated = True
    cp.security_status = CPSecurityStatus.ACTIVE
    response = await handle_driver_request(request)
    assert response.status == MessageStatus.ACCEPTED
```

---

## Migration from Release 1

### Backwards Compatibility

- **All Release 1 functionality preserved**
- **Existing CPs continue to work** (security initialized automatically)
- **No breaking changes** to public APIs
- **Database migrations** run automatically on startup

### Migration Steps

1. **Update code** with security extensions
2. **Run EV_Central** (database tables created automatically)
3. **Initialize security for existing CPs:**
   ```python
   for cp_id in existing_cp_ids:
       controller._initialize_cp_security(cp_id)
   ```
4. **Authenticate CPs** using EV_Registry credentials
5. **Monitor logs** for any authentication issues

---

## Monitoring & Observability

### Log Messages

```
[INFO] CP Security Service initialized
[INFO] CP CP-001 authenticated successfully (status: ACTIVE)
[WARNING] Authentication failed: CP CP-002 not found in registry
[WARNING] CP CP-003 REVOKED: Security violation detected
[INFO] Generated encryption key for CP CP-004
[WARNING] Revoked encryption key for CP CP-005
[ERROR] Decryption failed for CP CP-006: invalid key or corrupted data
```

### Metrics to Monitor

- Authentication success/failure rate
- Active vs. revoked CPs
- Key rotation frequency
- Encryption/decryption errors
- Auth failure counts per CP

---

## Troubleshooting

### Common Issues

**Issue:** Authentication fails with "CP not found in registry"
- **Solution:** Ensure CP is registered in EV_Registry first

**Issue:** Driver requests denied despite CP being online
- **Solution:** Check `cp.security_status` - may be OUT_OF_SERVICE or REVOKED

**Issue:** Decryption fails consistently
- **Solution:** Key may have been revoked or rotated; re-authenticate CP

**Issue:** Admin endpoints return 401
- **Solution:** Check `X-Admin-Key` header matches `EV_ADMIN_KEY` environment variable

---

## Production Deployment

### Security Checklist

- [ ] Change default secret keys (EV_SECURITY_SECRET, EV_ADMIN_KEY)
- [ ] Use strong passwords (32+ characters, high entropy)
- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Configure firewall rules (restrict admin API access)
- [ ] Set up key rotation schedule
- [ ] Enable audit logging
- [ ] Monitor authentication failures
- [ ] Implement rate limiting
- [ ] Use HSM/KMS for key storage (production)
- [ ] Set up alerting for security events
- [ ] Regular security audits
- [ ] Backup encryption keys (encrypted backups only)

---

## References

### Files Modified/Created

**New Files:**
- `evcharging/common/cp_security.py` - CP security service
- `evcharging/apps/ev_central/security_api.py` - Security REST API
- `EV_CENTRAL_SECURITY_IMPLEMENTATION.md` - This document

**Modified Files:**
- `evcharging/common/database.py` - Added security tables and CPSecurityDB
- `evcharging/apps/ev_central/main.py` - Integrated security service

### Dependencies

```txt
cryptography>=41.0.0  # AES-GCM encryption
passlib>=1.7.4        # Credential hashing
python-jose>=3.3.0    # JWT tokens
fastapi>=0.104.0      # Security API
pydantic>=2.0.0       # Request validation
```

---

## Conclusion

The EV_Central Security Extensions provide **production-grade security** for the EVCharging Network while maintaining full compatibility with Release 1. The implementation follows security best practices and provides comprehensive authentication, encryption, and access control mechanisms.

**Key Security Guarantees:**
- ✅ All CPs authenticated via EV_Registry credentials
- ✅ Per-CP unique encryption keys
- ✅ Key lifecycle management (generate/revoke/rotate)
- ✅ Status enforcement (ACTIVE/OUT_OF_SERVICE/REVOKED)
- ✅ Encrypted payload communication (AES-256-GCM)
- ✅ Comprehensive audit logging
- ✅ No breaking changes to existing functionality

For questions or issues, consult the security service logs or contact the development team.
