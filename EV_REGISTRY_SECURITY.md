# EV_Registry Security Hardening Guide

## Critical Security Issues Fixed

This document outlines the security improvements implemented to address the review findings.

### 1. Re-Registration Protection ✅

**Issue**: `/cp/register` previously allowed credential overwrites without authorization.

**Fix**: Registration now requires proof of ownership for existing CPs:

```python
# Re-registration requires EITHER:
# Option 1: Existing credentials
X-Existing-Credentials: <current-credentials>

# Option 2: Admin API key (if configured)
X-Registry-API-Key: <admin-key>
```

**Example**:
```bash
# Re-register with existing credentials
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Existing-Credentials: abc123..." \
  -d '{"cp_id": "CP-001", "location": "Berlin Updated"}'

# Re-register with admin key
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Registry-API-Key: admin-secret-key" \
  -d '{"cp_id": "CP-001", "location": "Berlin Updated"}'
```

### 2. Certificate Enforcement ✅

**Issue**: `require_certificate` config was ignored during authentication.

**Fix**: Certificate fingerprints are now validated when `REGISTRY_REQUIRE_CERTIFICATE=true`:

```bash
# Registration with certificate
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin",
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'

# Authentication requires matching fingerprint
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -H "X-Client-Cert-Fingerprint: AA:BB:CC:DD:..." \
  -d '{"cp_id": "CP-001", "credentials": "..."}'
```

### 3. TLS Enforcement ✅

**Issue**: TLS was optional and disabled by default, violating secure-channel requirement.

**Fix**: 
- `tls_enabled` now defaults to `true`
- Service fails fast if TLS config is incomplete (unless `allow_insecure=true` for dev)
- `allow_insecure` flag must be explicitly set for HTTP mode

**Configuration**:
```bash
# Production (TLS required)
REGISTRY_TLS_ENABLED=true
REGISTRY_TLS_CERT_FILE=/certs/cert.pem
REGISTRY_TLS_KEY_FILE=/certs/key.pem
REGISTRY_ALLOW_INSECURE=false  # Reject if TLS fails

# Development only (explicit insecure mode)
REGISTRY_TLS_ENABLED=false
REGISTRY_ALLOW_INSECURE=true  # Required to run HTTP
```

**Startup validation**:
```python
if config.tls_enabled and (not config.tls_cert_file or not config.tls_key_file):
    if not config.allow_insecure:
        raise ValueError("TLS configuration incomplete")

if not config.tls_enabled and not config.allow_insecure:
    raise ValueError("Secure transport required")
```

### 4. Strong Secret Requirements ✅

**Issue**: Default secrets were weak and predictable.

**Fix**:
- `secret_key` is now a **required** configuration parameter (no default)
- Minimum 32 characters enforced
- Docker Compose requires `REGISTRY_SECRET_KEY` environment variable
- Example `.env` file with strong key generation instructions

**Generate secrets**:
```bash
# Generate JWT secret key
openssl rand -hex 32

# Generate admin API key
openssl rand -hex 32

# Set in environment
export REGISTRY_SECRET_KEY="your-generated-secret-here"
export REGISTRY_ADMIN_API_KEY="your-admin-key-here"
```

### 5. Normalized Authentication Errors ✅

**Issue**: Different error codes leaked information about CP status.

**Fix**: All authentication failures now return **401 Unauthorized** with generic message:

```python
# Previously: 403 for deregistered CPs (information leak)
# Now: 401 for all auth failures

# Failed scenarios (all return 401):
- Unknown CP ID
- Invalid credentials
- Deregistered CP
- Missing/invalid certificate
- Expired token
```

**Error response**:
```json
{
  "error": "Authentication failed",
  "timestamp": "2025-12-11T10:30:00Z"
}
```

### 6. JWT Issuer/Audience Validation ✅

**Issue**: JWTs lacked issuer/audience claims and validation.

**Fix**: Full JWT validation with iss/aud claims:

```python
# Token creation includes:
{
  "sub": "CP-001",
  "iss": "ev-registry",      # NEW
  "aud": "ev-central",       # NEW
  "type": "cp_access",
  "iat": 1702281600,
  "exp": 1702368000,
  "nbf": 1702281600
}

# Verification enforces:
jwt.decode(
    token,
    algorithms=["HS256"],
    issuer="ev-registry",      # NEW: Verified
    audience="ev-central",     # NEW: Verified
    options={
        "verify_signature": True,
        "verify_exp": True,
        "verify_iat": True,
        "verify_aud": True,     # NEW
        "verify_iss": True      # NEW
    }
)
```

---

## Production Deployment Checklist

- [ ] **Generate strong secrets**:
  ```bash
  openssl rand -hex 32  # For REGISTRY_SECRET_KEY
  openssl rand -hex 32  # For REGISTRY_ADMIN_API_KEY
  ```

- [ ] **Configure TLS certificates**:
  ```bash
  # Generate self-signed cert (or use Let's Encrypt)
  openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes
  ```

- [ ] **Set environment variables**:
  ```bash
  export REGISTRY_SECRET_KEY="<strong-secret>"
  export REGISTRY_ADMIN_API_KEY="<admin-key>"
  export REGISTRY_TLS_ENABLED=true
  export REGISTRY_TLS_CERT_FILE=/certs/cert.pem
  export REGISTRY_TLS_KEY_FILE=/certs/key.pem
  export REGISTRY_ALLOW_INSECURE=false
  ```

- [ ] **Enable certificate authentication** (optional):
  ```bash
  export REGISTRY_REQUIRE_CERTIFICATE=true
  ```

- [ ] **Mount certificates in Docker**:
  ```yaml
  volumes:
    - ./certs/cert.pem:/certs/cert.pem:ro
    - ./certs/key.pem:/certs/key.pem:ro
  ```

- [ ] **Verify TLS is working**:
  ```bash
  curl https://localhost:8080/
  ```

- [ ] **Test re-registration protection**:
  ```bash
  # Should fail without credentials/admin key
  curl -X POST https://localhost:8080/cp/register \
    -H "Content-Type: application/json" \
    -d '{"cp_id": "EXISTING-CP", "location": "New Location"}'
  ```

- [ ] **Review logs for security events**:
  ```bash
  docker compose logs ev-registry | grep -i "unauthorized\|failed"
  ```

---

## Security Testing

### Test Re-Registration Protection

```bash
# 1. Register a CP
RESPONSE=$(curl -s -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "location": "Berlin"}')

CREDENTIALS=$(echo "$RESPONSE" | jq -r '.credentials')

# 2. Try re-registration without auth (should fail with 401)
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "location": "Munich"}'

# 3. Re-register with credentials (should succeed)
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Existing-Credentials: $CREDENTIALS" \
  -d '{"cp_id": "CP-TEST", "location": "Munich"}'
```

### Test Certificate Enforcement

```bash
# Start with certificate requirement
export REGISTRY_REQUIRE_CERTIFICATE=true

# Register with certificate
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-CERT",
    "location": "Berlin",
    "certificate_pem": "'"$(cat cert.pem)"'"
  }'

# Extract fingerprint
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in cert.pem | cut -d= -f2)

# Authenticate without cert (should fail with 401)
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-CERT", "credentials": "..."}'

# Authenticate with cert (should succeed)
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -H "X-Client-Cert-Fingerprint: $FINGERPRINT" \
  -d '{"cp_id": "CP-CERT", "credentials": "..."}'
```

### Test Error Normalization

```bash
# All these should return 401 with generic "Authentication failed"

# Unknown CP
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "UNKNOWN", "credentials": "fake"}'

# Deregistered CP
curl -X DELETE http://localhost:8080/cp/CP-TEST
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "credentials": "fake"}'

# Invalid credentials
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "credentials": "wrong"}'
```

---

## Migration from Insecure Deployment

If you have an existing deployment with weak security:

### 1. Backup existing registrations
```bash
docker compose exec ev-registry sqlite3 /data/ev_registry.db \
  ".dump cp_registry" > registry_backup.sql
```

### 2. Generate new secrets
```bash
openssl rand -hex 32 > registry_secret.txt
openssl rand -hex 32 > admin_key.txt
```

### 3. Update configuration
```bash
# .env file
REGISTRY_SECRET_KEY=$(cat registry_secret.txt)
REGISTRY_ADMIN_API_KEY=$(cat admin_key.txt)
REGISTRY_TLS_ENABLED=true
REGISTRY_ALLOW_INSECURE=false
```

### 4. Generate TLS certificates
```bash
# Self-signed (development)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=ev-registry"

# Or use Let's Encrypt (production)
certbot certonly --standalone -d your-domain.com
```

### 5. Update docker-compose.yml
```yaml
ev-registry:
  volumes:
    - ./certs/cert.pem:/certs/cert.pem:ro
    - ./certs/key.pem:/certs/key.pem:ro
  environment:
    REGISTRY_TLS_CERT_FILE: /certs/cert.pem
    REGISTRY_TLS_KEY_FILE: /certs/key.pem
```

### 6. Restart service
```bash
docker compose down
docker compose up -d ev-registry
```

### 7. Update all CP clients to use HTTPS
```bash
# Update CP Monitor configuration
CP_MONITOR_REGISTRY_URL=https://ev-registry:8080
```

---

## Monitoring & Auditing

### Security Events to Monitor

```bash
# Failed authentication attempts
docker compose logs ev-registry | grep "Authentication failed"

# Unauthorized re-registration attempts
docker compose logs ev-registry | grep "Unauthorized re-registration"

# Certificate validation failures
docker compose logs ev-registry | grep "Certificate fingerprint mismatch"

# TLS/security warnings
docker compose logs ev-registry | grep -i "insecure\|warning"
```

### Key Security Metrics

- **Failed auth rate**: Should be low; spike indicates attack
- **Re-registration attempts**: Track admin key usage
- **Certificate mismatches**: May indicate MITM or misconfiguration
- **Token validation failures**: Monitor for replay attacks

---

## Compliance Status

| Requirement | Status | Notes |
|-------------|--------|-------|
| Secure channel (TLS/HTTPS) | ✅ Fixed | Now enforced by default |
| Certificate authentication | ✅ Fixed | Implemented with fingerprint validation |
| Strong credentials | ✅ Fixed | Bcrypt with 64-char random generation |
| Re-registration protection | ✅ Fixed | Requires proof of ownership or admin key |
| JWT security | ✅ Fixed | Added iss/aud validation |
| Error normalization | ✅ Fixed | All auth failures return 401 |
| Shared database | ✅ Implemented | SQLite with proper schema |
| Admin controls | ✅ Fixed | Admin API key for privileged operations |

---

## Support & Questions

For security-related questions:
1. Review this document
2. Check `EV_REGISTRY_README.md` for API details
3. See `EV_REGISTRY_IMPLEMENTATION.md` for architecture
4. Test with updated `test_registry.sh` script

**Remember**: Security is not optional. Always use TLS, strong secrets, and certificate validation in production.
