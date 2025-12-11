# EV_Registry Quick Start Guide

## What is EV_Registry?

**EV_Registry** is the secure registration and authentication service for Charging Points (CPs) in the EVCharging Network (Release 2). CPs must register here first before they can connect to EV_Central and offer charging services.

---

## Quick Start (5 minutes)

### 1. Start the Service

```bash
# Option A: Start only EV_Registry
make registry

# Option B: Start with full system
make up
```

The service will be available at: **http://localhost:8080**

### 2. Access API Documentation

Open your browser: **http://localhost:8080/docs**

Interactive Swagger UI allows you to test all endpoints directly from the browser.

### 3. Register Your First CP

```bash
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin"
  }'
```

**Response:**
```json
{
  "cp_id": "CP-001",
  "status": "REGISTERED",
  "credentials": "a1b2c3d4e5f6...",  // Save this! Shown only once
  "token": "eyJhbGci...",             // JWT token for authentication
  "token_expires_at": "2025-12-12T10:30:00Z",
  "message": "CP registered successfully..."
}
```

⚠️ **Important**: Save the `credentials` value - it cannot be retrieved later!

### 4. Authenticate the CP

```bash
curl -X POST http://localhost:8080/cp/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "credentials": "a1b2c3d4e5f6..."
  }'
```

Returns a new JWT token valid for 24 hours (configurable).

### 5. Query CP Information

```bash
# Get specific CP
curl http://localhost:8080/cp/CP-001

# List all CPs
curl http://localhost:8080/cp

# List only registered CPs
curl "http://localhost:8080/cp?status_filter=REGISTERED"
```

### 6. Run Automated Tests

```bash
make registry-test
```

This runs comprehensive tests of all endpoints.

---

## Common Use Cases

### Use Case 1: CP Initial Setup

When deploying a new Charging Point:

1. **Register** with EV_Registry to get credentials
2. **Store credentials** securely in CP configuration
3. **Authenticate** before connecting to EV_Central
4. Use returned **JWT token** when communicating with EV_Central

### Use Case 2: CP Reconnection

When a CP restarts or loses connection:

1. **Authenticate** using stored credentials
2. Get a fresh JWT token
3. Use token for EV_Central connection

### Use Case 3: CP Decommissioning

When removing a CP from service:

```bash
curl -X DELETE http://localhost:8080/cp/CP-001
```

The CP is marked as DEREGISTERED and can no longer authenticate.

### Use Case 4: Certificate-Based Authentication

For production with client certificates:

```bash
curl -X POST http://localhost:8080/cp/register \
  -H "Content-Type: application/json" \
  -d '{
    "cp_id": "CP-001",
    "location": "Berlin",
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

EV_Registry extracts and stores the certificate fingerprint.

---

## Integration Examples

### Python (CP Monitor)

```python
import httpx
import os

class CPRegistryClient:
    def __init__(self, registry_url: str):
        self.registry_url = registry_url
        self.cp_id = None
        self.credentials = None
        self.token = None
    
    async def register(self, cp_id: str, location: str):
        """Register this CP with EV_Registry."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.registry_url}/cp/register",
                json={"cp_id": cp_id, "location": location}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.cp_id = cp_id
                self.credentials = data["credentials"]
                self.token = data["token"]
                
                # Store credentials securely
                os.environ[f"CP_{cp_id}_CREDENTIALS"] = self.credentials
                
                return True
        return False
    
    async def authenticate(self):
        """Authenticate and get fresh token."""
        async with httpx.AsyncClient() as client:
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
                return True
        return False

# Usage in EV_CP_M
registry_client = CPRegistryClient("http://ev-registry:8080")
await registry_client.register("CP-001", "Berlin")
```

### Shell Script (Automated Deployment)

```bash
#!/bin/bash

# Register multiple CPs in bulk
for i in {1..10}; do
    CP_ID=$(printf "CP-%03d" $i)
    LOCATION="Location-$i"
    
    echo "Registering $CP_ID..."
    
    RESPONSE=$(curl -s -X POST http://localhost:8080/cp/register \
        -H "Content-Type: application/json" \
        -d "{\"cp_id\": \"$CP_ID\", \"location\": \"$LOCATION\"}")
    
    CREDENTIALS=$(echo "$RESPONSE" | jq -r '.credentials')
    
    # Save to environment file
    echo "CP_${i}_ID=$CP_ID" >> .env
    echo "CP_${i}_CREDENTIALS=$CREDENTIALS" >> .env
done
```

---

## Configuration

### Environment Variables

```bash
# API Settings
REGISTRY_API_PORT=8080
REGISTRY_LOG_LEVEL=INFO

# Security
REGISTRY_SECRET_KEY=your-secret-key-change-in-production
REGISTRY_TOKEN_EXPIRATION_HOURS=24

# TLS (for production)
REGISTRY_TLS_ENABLED=true
REGISTRY_TLS_CERT_FILE=/path/to/cert.pem
REGISTRY_TLS_KEY_FILE=/path/to/key.pem

# Database
REGISTRY_DB_PATH=/data/ev_registry.db
```

### Docker Compose Override

Create `docker-compose.override.yml`:

```yaml
services:
  ev-registry:
    environment:
      REGISTRY_SECRET_KEY: "production-secret-key-here"
      REGISTRY_TOKEN_EXPIRATION_HOURS: 48
      REGISTRY_TLS_ENABLED: "true"
    volumes:
      - ./certs/cert.pem:/certs/cert.pem:ro
      - ./certs/key.pem:/certs/key.pem:ro
```

---

## Monitoring & Logs

### View Logs

```bash
# Real-time logs
make registry-logs

# Or with docker compose
docker compose logs -f ev-registry

# Last 100 lines
docker compose logs --tail=100 ev-registry
```

### Health Check

```bash
# Check if service is running
curl http://localhost:8080/

# Expected response:
{
  "service": "EV Registry",
  "status": "operational",
  "version": "2.0.0",
  "timestamp": "2025-12-11T10:30:00Z"
}
```

### Metrics

Check registration statistics:

```bash
# Count total CPs
curl http://localhost:8080/cp | jq '.total'

# Count registered CPs
curl "http://localhost:8080/cp?status_filter=REGISTERED" | jq '.total'

# Count deregistered CPs
curl "http://localhost:8080/cp?status_filter=DEREGISTERED" | jq '.total'
```

---

## Troubleshooting

### Problem: Service won't start

```bash
# Check logs
make registry-logs

# Check if port is already in use
lsof -i :8080

# Restart service
docker compose restart ev-registry
```

### Problem: Authentication fails

- Verify credentials are correct (they're case-sensitive)
- Check if CP is deregistered: `curl http://localhost:8080/cp/CP-ID`
- Verify token hasn't expired

### Problem: Database errors

```bash
# Reset database (WARNING: deletes all data)
docker compose down -v
docker compose up -d ev-registry
```

### Problem: Can't access API documentation

- Ensure service is running: `docker compose ps ev-registry`
- Check firewall: `curl http://localhost:8080/`
- View logs for errors: `make registry-logs`

---

## Security Best Practices

### Production Deployment

1. **Change the secret key**:
   ```bash
   REGISTRY_SECRET_KEY=$(openssl rand -hex 32)
   ```

2. **Enable TLS**:
   ```bash
   REGISTRY_TLS_ENABLED=true
   REGISTRY_TLS_CERT_FILE=/path/to/cert.pem
   REGISTRY_TLS_KEY_FILE=/path/to/key.pem
   ```

3. **Use strong credentials storage**:
   - Store CP credentials in secure vaults (e.g., HashiCorp Vault)
   - Never commit credentials to version control
   - Rotate credentials periodically

4. **Restrict network access**:
   ```bash
   # In docker-compose.yml, only expose to internal network
   ports: []  # Don't expose to host
   ```

5. **Enable certificate authentication**:
   ```bash
   REGISTRY_REQUIRE_CERTIFICATE=true
   ```

---

## Performance Tips

### High-Volume Deployments

For systems with 100+ CPs:

1. **Increase token expiration** to reduce authentication frequency:
   ```bash
   REGISTRY_TOKEN_EXPIRATION_HOURS=168  # 1 week
   ```

2. **Use connection pooling** in client code

3. **Implement token caching** on CP side

4. **Consider PostgreSQL** instead of SQLite for better concurrency:
   - Modify `database.py` to use PostgreSQL connector
   - Update `REGISTRY_DB_PATH` to PostgreSQL connection string

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test registration endpoint
ab -n 100 -c 10 -p register.json -T application/json \
   http://localhost:8080/cp/register
```

---

## Next Steps

1. **Read full documentation**: See `EV_REGISTRY_README.md`
2. **Integrate with EV_CP_M**: Update CP Monitor to register on startup
3. **Update EV_Central**: Query registry DB before accepting CP connections
4. **Enable TLS**: Set up certificates for production
5. **Implement monitoring**: Add Prometheus/Grafana for metrics

---

## Support & Resources

- **API Documentation**: http://localhost:8080/docs
- **Full README**: `EV_REGISTRY_README.md`
- **Test Script**: `./test_registry.sh`
- **Project Repository**: Check `README.md` for project overview

---

## Quick Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Health check |
| `/cp/register` | POST | Register new CP |
| `/cp/authenticate` | POST | Authenticate CP |
| `/cp/{cp_id}` | GET | Get CP info |
| `/cp/{cp_id}` | DELETE | Deregister CP |
| `/cp` | GET | List all CPs |

**Default Port**: 8080  
**Protocol**: HTTP (HTTPS in production)  
**Format**: JSON  
**Authentication**: Credentials + JWT tokens  
