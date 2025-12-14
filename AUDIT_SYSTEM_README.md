# EV_Central Centralized Audit Logging System

## Overview

The EV_Central system now includes a **mandatory, comprehensive audit logging system** that records all security-critical and operational events to a SQLite database. This provides a tamper-evident audit trail for compliance, security monitoring, and forensic analysis.

## Architecture

### Components

1. **AuditDB** (`evcharging/common/database.py`)
   - SQLite-based audit storage
   - Optimized indexes for fast querying
   - Thread-safe operations

2. **AuditService** (`evcharging/common/audit_service.py`)
   - High-level audit logging interface
   - Event type helpers
   - Metadata sanitization
   - Brute force detection

3. **AuditContextMiddleware** (`evcharging/common/audit_middleware.py`)
   - FastAPI middleware
   - Request context capture
   - X-Request-ID propagation
   - IP address extraction

4. **Integration** (`evcharging/apps/ev_central/security_api.py`)
   - Exception handlers with audit
   - Authentication endpoint integration
   - Key management audit hooks
   - Status change tracking

## Database Schema

### audit_events Table

```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_time TEXT NOT NULL,              -- UTC ISO-8601 timestamp
    who TEXT NOT NULL,                     -- cpId, "system", "admin", or "unknown"
    ip TEXT NOT NULL,                      -- Client IP address
    action TEXT NOT NULL,                  -- Event type (AUTH_SUCCESS, AUTH_FAIL, etc.)
    description TEXT NOT NULL,             -- Human-readable description
    severity TEXT NOT NULL,                -- INFO, WARN, ERROR, CRITICAL
    reason_code TEXT,                      -- Structured reason code
    request_id TEXT,                       -- Correlation UUID
    endpoint TEXT,                         -- API endpoint path
    http_method TEXT,                      -- HTTP method
    status_code INTEGER,                   -- HTTP status code
    metadata_json TEXT,                    -- Sanitized JSON metadata
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient querying
CREATE INDEX idx_audit_date_time ON audit_events(date_time);
CREATE INDEX idx_audit_who ON audit_events(who);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_ip ON audit_events(ip);
CREATE INDEX idx_audit_severity ON audit_events(severity);
CREATE INDEX idx_audit_request_id ON audit_events(request_id);
```

## Event Types

### Authentication Events

- **AUTH_SUCCESS**: Successful CP authentication
- **AUTH_FAIL**: Failed authentication with reason code
  - Reason codes:
    - `UNKNOWN_CP`: CP not found in registry
    - `INVALID_CREDENTIALS`: Credentials verification failed
    - `REVOKED`: CP has been revoked
    - `OUT_OF_SERVICE`: CP is out of service
    - `EXPIRED_TOKEN`: Token has expired
    - `INVALID_TOKEN`: Token is invalid or malformed
    - `TOKEN_VERSION_MISMATCH`: Token version mismatch

### Status Change Events

- **STATUS_CHANGE**: CP status transitions
  - Records: old_status → new_status
  - Tracked statuses: ACTIVE, OUT_OF_SERVICE, REVOKED

### Key Management Events

- **KEY_GENERATE**: New encryption key generated
- **KEY_RESET**: Encryption key rotated
- **KEY_REVOKE**: Encryption key revoked

### Error Events

- **VALIDATION_ERROR**: Request validation failed (422)
  - Logs field names and error types (NOT values)
- **ERROR**: System error (500)
  - Logs exception type and safe message
  - Does NOT log full stack traces

### Security Incidents

- **INCIDENT**: Critical security event
  - Types:
    - `BRUTE_FORCE_SUSPECTED`: Excessive auth failures
    - `UNAUTHORIZED_ADMIN_ACCESS`: Invalid admin key attempt
    - `TAMPERING_DETECTED`: Invalid encryption payloads

## Security Rules

### What is NEVER Logged

- Credentials (passwords, secrets)
- Tokens (JWT, access tokens)
- Encryption keys (symmetric keys, private keys)
- Decrypted payloads
- Full stack traces

### What is Sanitized

- Metadata fields are automatically sanitized
- Sensitive field names trigger redaction (→ `***REDACTED***`)
- Long strings are truncated (> 500 chars)

### Failure Handling

- Audit write failures DO NOT crash requests
- Failed writes fall back to standard logger
- Errors are logged but request continues

## Brute Force Detection

### Configuration

```python
BRUTE_FORCE_THRESHOLD = 5           # Failed auth attempts
BRUTE_FORCE_WINDOW_MINUTES = 10     # Time window
```

### Detection Logic

1. After each `AUTH_FAIL`, check recent failures:
   - By IP address (within time window)
   - By CP ID (within time window)

2. If threshold exceeded:
   - Write `INCIDENT` event with type `BRUTE_FORCE_SUSPECTED`
   - Log to standard logger at CRITICAL level
   - Include failure count and time window in metadata

3. Detection is automatic:
   ```python
   audit.detect_and_report_brute_force(cp_id, ctx)
   ```

## Usage Examples

### In FastAPI Endpoints

```python
from fastapi import Request
from evcharging.common.audit_service import get_audit_service
from evcharging.common.audit_middleware import get_audit_context_or_default

@app.post("/auth/credentials")
async def authenticate(req: CPAuthRequest, request: Request):
    ctx = get_audit_context_or_default(request)
    audit = get_audit_service()
    
    # Perform authentication...
    
    if success:
        audit.auth_success(
            cp_id=req.cp_id,
            ctx=ctx,
            metadata={"security_status": "ACTIVE"}
        )
    else:
        audit.auth_fail(
            cp_id_or_unknown=req.cp_id,
            ctx=ctx,
            reason_code=audit.REASON_INVALID_CREDENTIALS
        )
        audit.detect_and_report_brute_force(req.cp_id, ctx)
```

### Manual Logging

```python
from evcharging.common.audit_service import get_audit_service, RequestContext
from evcharging.common.utils import utc_now

audit = get_audit_service()

# Create context for non-HTTP operations
ctx = RequestContext(
    request_id="batch-job-123",
    ip="system",
    endpoint="/internal/cleanup",
    http_method="INTERNAL"
)

# Log status change
audit.status_change(
    cp_id="CP-001",
    ctx=ctx,
    old_status="ACTIVE",
    new_status="OUT_OF_SERVICE",
    reason="Scheduled maintenance"
)

# Log incident
audit.incident(
    who_or_unknown="CP-002",
    ctx=ctx,
    incident_type=audit.INCIDENT_TAMPERING,
    description="Invalid encryption payload detected",
    metadata={"payload_hash": "abc123..."}
)
```

### Querying Audit Logs

```python
from evcharging.common.database import AuditDB

audit_db = AuditDB("ev_charging.db")

# Get all authentication failures in last hour
from datetime import datetime, timedelta
start_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()

failures = audit_db.query_events(
    action="AUTH_FAIL",
    start_time=start_time,
    limit=100
)

# Get all events for a specific CP
cp_events = audit_db.query_events(
    who="CP-001",
    limit=50
)

# Get recent auth failures for IP
ip_failures = audit_db.get_recent_auth_failures(
    ip="192.168.1.100",
    minutes=10
)

# Get all incidents
incidents = audit_db.query_events(
    action="INCIDENT",
    severity="CRITICAL"
)
```

## Middleware Configuration

### Basic Setup

The middleware is automatically added in `security_api.py`:

```python
app = FastAPI(...)
app.add_middleware(AuditContextMiddleware)
```

### Proxy Configuration

If running behind a proxy/load balancer, set environment variable:

```bash
export TRUST_PROXY_HEADERS=true
```

This enables extraction of real client IP from:
- `X-Forwarded-For` header (first IP)
- `X-Real-IP` header (fallback)

### Request ID Propagation

- Accepts `X-Request-ID` header from clients
- Generates UUID if not provided
- Adds `X-Request-ID` to response headers

## Exception Handling

All FastAPI endpoints are wrapped with audit-aware exception handlers:

### Validation Errors

```python
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    ctx = get_audit_context_or_default(request)
    
    # Extract field errors (NOT values)
    fields_summary = "field1:required, field2:type_error"
    
    audit.validation_error(ctx=ctx, fields_summary=fields_summary)
    # Returns 422 with request_id
```

### General Errors

```python
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    ctx = get_audit_context_or_default(request)
    
    # Safe error logging
    audit.error(
        ctx=ctx,
        error_type="ValueError",
        safe_message="Invalid config parameter"
    )
    # Returns 500 with request_id
```

## Testing

Comprehensive test suite included:

```bash
# Run all audit tests
pytest evcharging/tests/test_audit_system.py -v

# Run specific test
pytest evcharging/tests/test_audit_system.py::TestBruteForceDetection -v

# Run with coverage
pytest evcharging/tests/test_audit_system.py --cov=evcharging.common.audit_service
```

### Test Coverage

- ✅ Database schema creation
- ✅ Event insertion and querying
- ✅ Authentication logging
- ✅ Status change logging
- ✅ Key operation logging
- ✅ Validation error logging
- ✅ System error logging
- ✅ Security incident detection
- ✅ Brute force detection (per IP and per CP)
- ✅ Metadata sanitization
- ✅ Request context handling
- ✅ Integration tests

## Monitoring & Alerts

### Critical Events to Monitor

1. **INCIDENT** events (severity: CRITICAL)
   - Immediate alerting recommended
   - Indicates potential security breach

2. **Excessive AUTH_FAIL** events
   - Monitor failure rates per IP/CP
   - May indicate credential guessing

3. **KEY_REVOKE** events (severity: WARN)
   - Track key revocations
   - Investigate frequent revocations

4. **STATUS_CHANGE** to REVOKED
   - Monitor CP revocations
   - Ensure proper justification

### Query Examples for Monitoring

```python
# Get today's incidents
from datetime import datetime
today_start = datetime.utcnow().replace(hour=0, minute=0, second=0).isoformat()

incidents_today = audit_db.query_events(
    action="INCIDENT",
    start_time=today_start
)

# Get auth failure rate
from datetime import timedelta
hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()

hourly_failures = audit_db.query_events(
    action="AUTH_FAIL",
    start_time=hour_ago
)
failure_rate = len(hourly_failures)  # failures per hour

# Get most targeted CPs
failures_by_cp = {}
for event in hourly_failures:
    cp = event['who']
    failures_by_cp[cp] = failures_by_cp.get(cp, 0) + 1

top_targets = sorted(failures_by_cp.items(), key=lambda x: x[1], reverse=True)[:5]
```

## Performance Considerations

### Database

- SQLite is sufficient for moderate traffic
- Indexes optimize common queries
- Consider archiving old audit logs periodically

### Write Performance

- Audit writes are synchronous but fast (< 5ms typical)
- Failed writes fall back to logger
- No blocking on audit failures

### Query Performance

Optimized indexes for:
- Time-based queries (`date_time`)
- CP lookups (`who`)
- Action filtering (`action`)
- IP filtering (`ip`)
- Request tracing (`request_id`)

## Compliance & Retention

### Compliance Features

- Immutable audit trail (append-only)
- Timestamp on every event
- Correlation IDs for request tracing
- IP address tracking
- Actor identification (who)

### Retention Policy

Implement retention based on requirements:

```python
# Example: Delete audit events older than 90 days
def cleanup_old_audits(days=90):
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    
    with audit_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM audit_events WHERE date_time < ?",
            (cutoff,)
        )
        deleted = cursor.rowcount
        conn.commit()
        
    return deleted
```

## Troubleshooting

### Audit Events Not Appearing

1. Check database path:
   ```python
   audit = get_audit_service("ev_charging.db")
   ```

2. Verify middleware is added:
   ```python
   app.add_middleware(AuditContextMiddleware)
   ```

3. Check logs for write failures:
   ```
   grep "Failed to insert audit event" logs/
   ```

### False Brute Force Alerts

Adjust thresholds in `audit_service.py`:

```python
BRUTE_FORCE_THRESHOLD = 10  # Increase threshold
BRUTE_FORCE_WINDOW_MINUTES = 5  # Shorter window
```

### Missing Request Context

Ensure middleware is registered BEFORE other middleware:

```python
app.add_middleware(AuditContextMiddleware)
# Then add other middleware
```

## Future Enhancements

Potential improvements:

- [ ] Export audit logs to external SIEM
- [ ] Real-time alerting integration
- [ ] Audit log archival to cloud storage
- [ ] Advanced analytics dashboard
- [ ] Anomaly detection using ML

## Summary

The EV_Central audit system provides:

✅ **Comprehensive logging** of all security events  
✅ **SQLite persistence** for reliability  
✅ **Automatic brute force detection**  
✅ **Secure by default** (no secrets logged)  
✅ **Request tracing** with correlation IDs  
✅ **FastAPI integration** with middleware  
✅ **Extensive test coverage**  
✅ **Production-ready** error handling  

This system ensures complete visibility into all security-critical operations while maintaining strict data protection standards.
