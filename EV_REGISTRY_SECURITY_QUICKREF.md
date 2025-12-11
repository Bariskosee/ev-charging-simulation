# EV_Registry Security Fixes - Quick Reference

## Critical Security Issues - Fixed ✅

### 1. Re-Registration Takeover Prevention

**Before**: Anyone could overwrite CP credentials
**After**: Requires proof of ownership

**How to re-register**:
```bash
# Option 1: Using existing credentials
curl -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Existing-Credentials: <current-credentials>" \
  -d '{"cp_id": "CP-001", "location": "Updated Location"}'

# Option 2: Using admin API key
curl -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Registry-API-Key: <admin-key>" \
  -d '{"cp_id": "CP-001", "location": "Updated Location"}'
```

---

### 2. Certificate Enforcement

**Before**: Certificate requirement ignored
**After**: Validates certificate fingerprints when required

**Configuration**:
```bash
export REGISTRY_REQUIRE_CERTIFICATE=true
```

**Usage**:
```bash
# Extract fingerprint from certificate
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in cert.pem | cut -d= -f2)

# Include in authentication
curl -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -H "X-Client-Cert-Fingerprint: $FINGERPRINT" \
  -d '{"cp_id": "CP-001", "credentials": "<credentials>"}'
```

---

### 3. TLS Required by Default

**Before**: HTTP mode enabled by default
**After**: TLS enabled by default, must explicitly allow insecure

**Production (TLS required)**:
```bash
export REGISTRY_TLS_ENABLED=true
export REGISTRY_TLS_CERT_FILE=/certs/cert.pem
export REGISTRY_TLS_KEY_FILE=/certs/key.pem
export REGISTRY_ALLOW_INSECURE=false
```

**Development only (explicit insecure)**:
```bash
export REGISTRY_TLS_ENABLED=false
export REGISTRY_ALLOW_INSECURE=true  # Required for HTTP
```

---

### 4. Strong Secret Requirements

**Before**: Weak default secrets
**After**: No defaults, must generate strong secrets

**Generate secrets**:
```bash
# JWT secret key (minimum 32 characters)
openssl rand -hex 32

# Admin API key
openssl rand -hex 32
```

**Configuration**:
```bash
export REGISTRY_SECRET_KEY="<64-char-hex-from-above>"
export REGISTRY_ADMIN_API_KEY="<64-char-hex-from-above>"
```

---

### 5. Error Normalization

**Before**: Different errors leaked CP status
**After**: All auth failures return generic 401

**All scenarios return 401**:
- Unknown CP ID
- Invalid credentials
- Deregistered CP
- Missing certificate
- Invalid certificate

**Response**:
```json
{
  "error": "Authentication failed",
  "timestamp": "2025-12-11T10:30:00Z"
}
```

---

## Quick Setup Guide

### 1. Generate Secrets
```bash
# Create secrets directory
mkdir -p secrets

# Generate JWT secret
openssl rand -hex 32 > secrets/registry_secret.txt

# Generate admin key
openssl rand -hex 32 > secrets/admin_key.txt
```

### 2. Generate TLS Certificates
```bash
# Create certs directory
mkdir -p certs

# Self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=ev-registry"

# Production: Use Let's Encrypt
# certbot certonly --standalone -d your-domain.com
```

### 3. Configure Environment
```bash
# Create .env file
cat > .env << EOF
REGISTRY_SECRET_KEY=$(cat secrets/registry_secret.txt)
REGISTRY_ADMIN_API_KEY=$(cat secrets/admin_key.txt)
REGISTRY_TLS_ENABLED=true
REGISTRY_TLS_CERT_FILE=/certs/cert.pem
REGISTRY_TLS_KEY_FILE=/certs/key.pem
REGISTRY_ALLOW_INSECURE=false
REGISTRY_REQUIRE_CERTIFICATE=false
EOF
```

### 4. Update docker-compose.yml
```yaml
ev-registry:
  volumes:
    - ./certs/cert.pem:/certs/cert.pem:ro
    - ./certs/key.pem:/certs/key.pem:ro
  environment:
    - REGISTRY_SECRET_KEY=${REGISTRY_SECRET_KEY}
    - REGISTRY_ADMIN_API_KEY=${REGISTRY_ADMIN_API_KEY}
    - REGISTRY_TLS_ENABLED=${REGISTRY_TLS_ENABLED}
    - REGISTRY_TLS_CERT_FILE=${REGISTRY_TLS_CERT_FILE}
    - REGISTRY_TLS_KEY_FILE=${REGISTRY_TLS_KEY_FILE}
```

### 5. Start Service
```bash
docker compose up -d ev-registry
```

### 6. Verify Security
```bash
# Check TLS
curl -k https://localhost:8080/

# Test re-registration protection
./test_registry.sh
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REGISTRY_SECRET_KEY` | **YES** | None | JWT secret (min 32 chars) |
| `REGISTRY_ADMIN_API_KEY` | **YES** | None | Admin operations key |
| `REGISTRY_TLS_ENABLED` | No | `true` | Enable TLS/HTTPS |
| `REGISTRY_TLS_CERT_FILE` | If TLS | None | Path to certificate |
| `REGISTRY_TLS_KEY_FILE` | If TLS | None | Path to private key |
| `REGISTRY_ALLOW_INSECURE` | No | `false` | Allow HTTP (dev only) |
| `REGISTRY_REQUIRE_CERTIFICATE` | No | `false` | Require client certs |
| `REGISTRY_JWT_ISSUER` | No | `ev-registry` | JWT issuer claim |
| `REGISTRY_JWT_AUDIENCE` | No | `ev-central` | JWT audience claim |
| `REGISTRY_JWT_EXPIRATION` | No | `86400` | Token expiry (seconds) |

---

## Testing Security Features

### Test Re-Registration Protection
```bash
# Register a CP
RESPONSE=$(curl -k -s -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "location": "Berlin"}')

CREDENTIALS=$(echo "$RESPONSE" | jq -r '.credentials')

# Try re-registration without auth (should fail with 401)
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "location": "Munich"}'

# Re-register with credentials (should succeed)
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Existing-Credentials: $CREDENTIALS" \
  -d '{"cp_id": "CP-TEST", "location": "Munich"}'
```

### Test Certificate Validation
```bash
# Set certificate requirement
export REGISTRY_REQUIRE_CERTIFICATE=true

# Register with certificate
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-CERT",
    "location": "Berlin",
    "certificate_pem": "'"$(cat certs/cert.pem)"'"
  }'

# Get fingerprint
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in certs/cert.pem | cut -d= -f2)

# Auth without cert (should fail)
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-CERT", "credentials": "..."}'

# Auth with cert (should succeed)
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -H "X-Client-Cert-Fingerprint: $FINGERPRINT" \
  -d '{"cp_id": "CP-CERT", "credentials": "..."}'
```

### Test Error Normalization
```bash
# All should return 401 with generic message

# Unknown CP
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "UNKNOWN", "credentials": "fake"}'

# Deregistered CP
curl -k -X DELETE https://localhost:8080/cp/CP-TEST
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-TEST", "credentials": "fake"}'

# Invalid credentials
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "CP-001", "credentials": "wrong"}'
```

---

## Common Operations

### Register New CP
```bash
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin Hauptbahnhof",
    "metadata": {"power_rating": "22kW", "type": "AC"}
  }'
```

### Update Existing CP (with credentials)
```bash
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Existing-Credentials: <current-credentials>" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin Alexanderplatz"
  }'
```

### Update Existing CP (with admin key)
```bash
curl -k -X POST https://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -H "X-Registry-API-Key: <admin-key>" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin Alexanderplatz"
  }'
```

### Authenticate CP
```bash
curl -k -X POST https://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "credentials": "<credentials>"
  }'
```

### Deregister CP
```bash
curl -k -X DELETE https://localhost:8080/cp/CP-001
```

### List All CPs
```bash
curl -k https://localhost:8080/cp
```

### Get CP Details
```bash
curl -k https://localhost:8080/cp/CP-001
```

---

## Troubleshooting

### "TLS configuration incomplete"
**Cause**: TLS enabled but certificate files not configured
**Fix**:
```bash
export REGISTRY_TLS_CERT_FILE=/certs/cert.pem
export REGISTRY_TLS_KEY_FILE=/certs/key.pem
# OR for development only:
export REGISTRY_ALLOW_INSECURE=true
```

### "Secret key must be at least 32 characters"
**Cause**: Secret key too short or missing
**Fix**:
```bash
export REGISTRY_SECRET_KEY=$(openssl rand -hex 32)
```

### "Unauthorized: Re-registration requires valid credentials"
**Cause**: Trying to update existing CP without authorization
**Fix**:
```bash
# Include credentials or admin key in request
curl -H "X-Existing-Credentials: <creds>" ...
# OR
curl -H "X-Registry-API-Key: <admin-key>" ...
```

### "Authentication failed" (401)
**Possible causes**:
- Invalid credentials
- CP deregistered
- Certificate required but not provided
- Certificate fingerprint mismatch

**Debug**:
```bash
# Check CP status
curl -k https://localhost:8080/cp/CP-001

# Verify certificate fingerprint
openssl x509 -noout -fingerprint -sha256 -in cert.pem
```

---

## Security Monitoring

### Check Logs for Security Events
```bash
# Failed authentication attempts
docker compose logs ev-registry | grep "Authentication failed"

# Unauthorized re-registration attempts
docker compose logs ev-registry | grep "Unauthorized re-registration"

# Certificate validation failures
docker compose logs ev-registry | grep "Certificate fingerprint mismatch"

# Security warnings
docker compose logs ev-registry | grep -i "warning\|insecure"
```

### Key Metrics to Monitor
- Failed authentication rate (should be low)
- Re-registration attempts (track admin key usage)
- Certificate mismatches (may indicate MITM)
- Token validation failures (replay attacks)

---

## Documentation Links

- **Comprehensive Security Guide**: `EV_REGISTRY_SECURITY.md`
- **API Reference**: `EV_REGISTRY_README.md`
- **Implementation Details**: `EV_REGISTRY_IMPLEMENTATION.md`
- **Integration Guide**: `EV_REGISTRY_INTEGRATION.md`
- **Security Checklist**: `EV_REGISTRY_SECURITY_CHECKLIST.md`
- **Configuration Template**: `.env.example`

---

## Support

For security questions:
1. Review this quick reference
2. Check `EV_REGISTRY_SECURITY.md` for detailed guides
3. Run `./test_registry.sh` to verify setup
4. Check logs for specific error details

**Remember**: All security features are mandatory in production. Never disable TLS or use weak secrets.
