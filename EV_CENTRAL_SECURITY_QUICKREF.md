# EV_Central Security Extensions - Quick Reference

## 🚀 Quick Start

### Import Security Components
```python
from evcharging.common.cp_security import (
    CPSecurityService,
    CPSecurityStatus,
    CPEncryptionService
)
from evcharging.common.database import CPSecurityDB, CPRegistryDB
from evcharging.common.security import create_security_manager
```

---

## 🔐 Common Operations

### 1. Initialize Security for a CP
```python
# In EVCentralController
def _initialize_cp_security(self, cp_id: str):
    # Initialize security status (ACTIVE by default)
    self.security_db.initialize_cp_security(cp_id)
    
    # Generate encryption key
    self.cp_security.generate_key_for_cp(cp_id)
```

### 2. Authenticate a CP
```python
# With credentials
auth_result = controller.cp_security.authenticate_cp(
    cp_id="CP-001",
    credentials="secret-from-registry"
)

if auth_result.is_authorized():
    token = auth_result.token
    # CP is ACTIVE and can operate
else:
    # Auth failed or CP is REVOKED/OUT_OF_SERVICE
    print(f"Denied: {auth_result.reason}")
    print(f"Status: {auth_result.status.value}")
```

### 3. Verify JWT Token
```python
auth_result = controller.cp_security.verify_token(token)

if auth_result and auth_result.is_authorized():
    cp_id = auth_result.cp_id
    # Token valid and CP is ACTIVE
```

### 4. Check CP Authorization
```python
cp = controller.charging_points[cp_id]

if cp.is_security_authorized():
    # CP is authenticated, ACTIVE, and has encryption key
    # Proceed with operation
else:
    # Deny operation
```

### 5. Encrypt Payload for CP
```python
command = {
    "type": "START_SUPPLY",
    "session_id": "sess-123",
    "driver_id": "driver-001"
}

encrypted = controller.cp_security.encrypt_for_cp(cp_id, command)
# Send encrypted to CP
```

### 6. Decrypt Payload from CP
```python
# Receive encrypted from CP
try:
    decrypted = controller.cp_security.decrypt_from_cp(
        cp_id,
        encrypted_payload
    )
    # Process decrypted payload
except ValueError:
    # Decryption failed - invalid key or tampered data
    # Reject request
```

### 7. Revoke a CP (Permanent)
```python
controller.revoke_cp_access(
    cp_id="CP-001",
    reason="Security violation detected"
)
# CP is now REVOKED - cannot be restored
```

### 8. Set CP Out of Service
```python
controller.set_cp_out_of_service(
    cp_id="CP-001",
    reason="Scheduled maintenance"
)
# CP can authenticate but cannot operate
```

### 9. Restore CP to Active
```python
controller.restore_cp_to_active(cp_id="CP-001")
# CP returns to full operation
```

### 10. Rotate Encryption Key
```python
controller.cp_security.reset_key_for_cp(cp_id="CP-001")
# Old key revoked, new key generated
```

---

## 🛡️ Security Status Values

| Status | Authentication | Operations | Restoration |
|--------|---------------|------------|-------------|
| `ACTIVE` | ✅ Succeeds | ✅ Allowed | N/A |
| `OUT_OF_SERVICE` | ✅ Succeeds | ❌ Blocked | ✅ Possible |
| `REVOKED` | ❌ Fails | ❌ Blocked | ❌ Permanent |

---

## 🔑 ChargingPoint Security Attributes

```python
class ChargingPoint:
    is_authenticated: bool         # Has valid auth
    auth_token: str | None         # JWT token
    security_status: CPSecurityStatus  # ACTIVE/OUT_OF_SERVICE/REVOKED
    last_auth_time: datetime | None    # Last successful auth
    has_encryption_key: bool       # Encryption key exists
    
    def is_security_authorized(self) -> bool:
        """Check if CP can perform operations"""
        return (
            self.is_authenticated and 
            self.security_status == CPSecurityStatus.ACTIVE and
            self.has_encryption_key
        )
```

---

## 🌐 REST API Quick Reference

### Authentication Endpoints
```bash
# Authenticate with credentials
curl -X POST http://localhost:8000/auth/credentials \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "credentials": "secret"}'

# Authenticate with token
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "token": "eyJhbGc..."}'
```

### Admin Endpoints (Require X-Admin-Key Header)
```bash
# Generate encryption key
curl -X POST http://localhost:8000/keys/generate \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001"}'

# Revoke key
curl -X POST http://localhost:8000/keys/revoke \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001"}'

# Reset (rotate) key
curl -X POST http://localhost:8000/keys/reset \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001"}'

# Revoke CP access
curl -X POST http://localhost:8000/status/revoke \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "reason": "Security violation"}'

# Set out of service
curl -X POST http://localhost:8000/status/out-of-service \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "reason": "Maintenance"}'

# Restore to active
curl -X POST http://localhost:8000/status/restore \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001"}'
```

### Monitoring Endpoints
```bash
# Get CP security status
curl http://localhost:8000/security/status/CP-001

# Get all CP statuses
curl http://localhost:8000/security/status

# Health check
curl http://localhost:8000/health
```

---

## 📊 Database Queries

### Check CP Security Status
```sql
SELECT cp_id, registration_status, last_authenticated_at, auth_failure_count
FROM cp_security_status
WHERE cp_id = 'CP-001';
```

### Get Encryption Key Info
```sql
SELECT cp_id, key_version, status, key_created_at, key_rotated_at
FROM cp_encryption_keys
WHERE cp_id = 'CP-001';
```

### Find Revoked CPs
```sql
SELECT cp_id, revocation_reason, revoked_at
FROM cp_security_status
WHERE registration_status = 'REVOKED';
```

### List CPs by Status
```sql
SELECT cp_id, registration_status, last_authenticated_at
FROM cp_security_status
ORDER BY updated_at DESC;
```

---

## ⚠️ Error Handling

### Authentication Errors
```python
auth_result = controller.cp_security.authenticate_cp(cp_id, credentials)

if not auth_result.success:
    if "not found" in auth_result.reason:
        # CP not registered in EV_Registry
        return 404
    elif "Invalid credentials" in auth_result.reason:
        # Wrong credentials
        return 401
    elif auth_result.status == CPSecurityStatus.REVOKED:
        # CP is revoked
        return 403
    elif auth_result.status == CPSecurityStatus.OUT_OF_SERVICE:
        # CP is out of service
        return 403
```

### Encryption Errors
```python
try:
    decrypted = controller.cp_security.decrypt_from_cp(cp_id, encrypted)
except ValueError:
    # Invalid key, tampered data, or corrupted payload
    # Log as potential security incident
    logger.warning(f"Decryption failed for CP {cp_id}")
    return 400  # Bad Request
```

---

## 🔒 Security Best Practices

### DO ✅
- Use strong secret keys (32+ characters)
- Rotate encryption keys regularly (every 30-90 days)
- Monitor authentication failure counts
- Log all REVOKED operations
- Use HTTPS/TLS in production
- Set token expiration appropriately
- Validate tokens on every request
- Handle decryption failures as potential attacks

### DON'T ❌
- Log credentials or encryption keys (plaintext or hashed)
- Store keys in plaintext anywhere
- Share encryption keys between CPs
- Ignore authentication failures
- Use default secret keys in production
- Skip token validation
- Allow operations on OUT_OF_SERVICE or REVOKED CPs

---

## 🧪 Testing

### Unit Test Template
```python
def test_cp_authentication():
    # Setup
    security_service = CPSecurityService(...)
    
    # Test successful auth
    result = security_service.authenticate_cp(cp_id, valid_credentials)
    assert result.success
    assert result.is_authorized()
    assert result.token is not None
    
    # Test invalid credentials
    result = security_service.authenticate_cp(cp_id, invalid_credentials)
    assert not result.success
```

### Integration Test Template
```python
async def test_driver_request_with_security():
    # Setup
    cp = controller.charging_points[cp_id]
    
    # Test unauthorized CP
    cp.is_authenticated = False
    response = await controller.handle_driver_request(request)
    assert response.status == MessageStatus.DENIED
    
    # Test authorized CP
    cp.is_authenticated = True
    cp.security_status = CPSecurityStatus.ACTIVE
    cp.has_encryption_key = True
    response = await controller.handle_driver_request(request)
    assert response.status == MessageStatus.ACCEPTED
```

---

## 📝 Environment Variables

```bash
# Required in production
export EV_SECURITY_SECRET="your-secret-minimum-32-chars!!!"
export EV_ADMIN_KEY="your-admin-key"

# Optional
export EV_DB_PATH="ev_charging.db"
export EV_TOKEN_EXPIRATION_HOURS=24
```

---

## 🐛 Troubleshooting

### Issue: Authentication fails
**Check:**
1. CP registered in EV_Registry?
2. Credentials correct?
3. CP status in `cp_security_status` table?

### Issue: Decryption fails
**Check:**
1. Encryption key exists for CP?
2. Key status is ACTIVE?
3. Payload not corrupted in transit?

### Issue: Operations denied despite auth
**Check:**
1. `cp.security_status` - may be OUT_OF_SERVICE or REVOKED
2. `cp.has_encryption_key` - must be true
3. `cp.is_authenticated` - must be true

---

## 📚 Related Documentation

- **`EV_CENTRAL_SECURITY_IMPLEMENTATION.md`** - Complete implementation guide
- **`EV_CENTRAL_SECURITY_SUMMARY.md`** - Executive summary
- **`examples/security_examples.py`** - Working code examples
- **Inline code documentation** - All classes and methods documented

---

## 💡 Key Concepts

### Root of Trust
- EV_Registry issues credentials during CP registration
- EV_Central validates credentials but does NOT register CPs
- Credentials are the foundation of the security model

### Defense in Depth
1. **Layer 1:** Transport security (HTTPS/TLS)
2. **Layer 2:** Authentication (credentials + tokens)
3. **Layer 3:** Authorization (status checks)
4. **Layer 4:** Encryption (AES-256-GCM payloads)

### Fail-Secure Design
- Authentication failures → deny access
- Decryption failures → reject payload
- Invalid status → block operations
- Missing key → operations forbidden

---

## 🎯 Common Patterns

### Pattern 1: New CP Onboarding
```python
# 1. CP registers with EV_Registry (gets credentials)
# 2. CP appears in EV_Central
controller.register_cp(registration)
# 3. Initialize security
controller._initialize_cp_security(cp_id)
# 4. CP authenticates
auth_result = controller.cp_security.authenticate_cp(cp_id, credentials)
# 5. CP can now operate
```

### Pattern 2: Request Validation
```python
async def handle_request(self, request):
    cp = self.charging_points.get(request.cp_id)
    
    # Security check
    if not cp.is_security_authorized():
        await self._send_denial(request, 
            f"Not authorized: {cp.security_status.value}")
        return
    
    # Proceed with operation
    ...
```

### Pattern 3: Emergency Revocation
```python
# Detect security incident
if security_incident_detected(cp_id):
    # Immediate revocation
    controller.revoke_cp_access(cp_id, reason="Security incident")
    
    # Stop active sessions
    if cp.current_session:
        await controller.send_stop_supply_command(cp_id)
    
    # Alert administrators
    send_security_alert(cp_id, "CP revoked due to incident")
```

---

## 📞 Support

For issues or questions:
1. Check this quick reference
2. Review `EV_CENTRAL_SECURITY_IMPLEMENTATION.md`
3. Run `examples/security_examples.py`
4. Examine logs for error details

---

*Last updated: December 14, 2025*
