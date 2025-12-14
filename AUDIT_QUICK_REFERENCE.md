# Audit System Quick Reference

## Common Operations

### Import Required Modules

```python
from evcharging.common.audit_service import get_audit_service, RequestContext
from evcharging.common.audit_middleware import get_audit_context_or_default
from evcharging.common.database import AuditDB
```

## In FastAPI Endpoints

### Get Audit Service and Context

```python
@app.post("/endpoint")
async def handler(request: Request):
    ctx = get_audit_context_or_default(request)
    audit = get_audit_service()
    # Use audit and ctx...
```

### Log Authentication Success

```python
audit.auth_success(
    cp_id="CP-001",
    ctx=ctx,
    metadata={"security_status": "ACTIVE"}
)
```

### Log Authentication Failure

```python
audit.auth_fail(
    cp_id_or_unknown="CP-001",
    ctx=ctx,
    reason_code=audit.REASON_INVALID_CREDENTIALS,
    description="Invalid credentials",
    metadata={"attempt_count": 3}
)

# Check for brute force
audit.detect_and_report_brute_force("CP-001", ctx)
```

### Log Status Change

```python
audit.status_change(
    cp_id="CP-001",
    ctx=ctx,
    old_status="ACTIVE",
    new_status="OUT_OF_SERVICE",
    reason="Scheduled maintenance"
)
```

### Log Key Operations

```python
# Generate
audit.key_generate(cp_id="CP-001", ctx=ctx)

# Reset
audit.key_reset(
    cp_id="CP-001",
    ctx=ctx,
    reason="Security rotation"
)

# Revoke
audit.key_revoke(
    cp_id="CP-001",
    ctx=ctx,
    reason="CP compromised"
)
```

### Log Validation Error

```python
# In exception handler
fields_summary = "cp_id:required, credentials:too_short"
audit.validation_error(
    ctx=ctx,
    fields_summary=fields_summary,
    who="unknown"
)
```

### Log System Error

```python
audit.error(
    ctx=ctx,
    error_type="ValueError",
    safe_message="Invalid configuration",
    who="system"
)
```

### Log Security Incident

```python
audit.incident(
    who_or_unknown="CP-001",
    ctx=ctx,
    incident_type=audit.INCIDENT_BRUTE_FORCE,
    description="Brute force attack detected",
    metadata={"failure_count": 10}
)
```

## Querying Audit Logs

### Initialize Database

```python
audit_db = AuditDB("ev_charging.db")
```

### Get All Events

```python
events = audit_db.query_events(limit=100)
```

### Filter by Action

```python
auth_failures = audit_db.query_events(
    action="AUTH_FAIL",
    limit=50
)
```

### Filter by CP

```python
cp_events = audit_db.query_events(
    who="CP-001",
    limit=100
)
```

### Filter by IP

```python
ip_events = audit_db.query_events(
    ip="192.168.1.100",
    limit=50
)
```

### Filter by Severity

```python
critical_events = audit_db.query_events(
    severity="CRITICAL",
    limit=100
)
```

### Filter by Time Range

```python
from datetime import datetime, timedelta

start = (datetime.utcnow() - timedelta(hours=24)).isoformat()
end = datetime.utcnow().isoformat()

recent_events = audit_db.query_events(
    start_time=start,
    end_time=end,
    limit=200
)
```

### Get Recent Auth Failures

```python
# By IP
ip_failures = audit_db.get_recent_auth_failures(
    ip="10.0.0.1",
    minutes=10
)

# By CP
cp_failures = audit_db.get_recent_auth_failures(
    cp_id="CP-001",
    minutes=10
)

# Both
specific_failures = audit_db.get_recent_auth_failures(
    ip="10.0.0.1",
    cp_id="CP-001",
    minutes=10
)
```

## Action Types

### Authentication
- `AUTH_SUCCESS` - Successful authentication
- `AUTH_FAIL` - Failed authentication

### Status Changes
- `STATUS_CHANGE` - CP status changed

### Key Management
- `KEY_GENERATE` - Encryption key generated
- `KEY_RESET` - Encryption key reset/rotated
- `KEY_REVOKE` - Encryption key revoked

### Errors
- `VALIDATION_ERROR` - Request validation failed
- `ERROR` - System error

### Security
- `INCIDENT` - Security incident

## Reason Codes

### Authentication Failures
- `REASON_UNKNOWN_CP` - CP not in registry
- `REASON_INVALID_CREDENTIALS` - Bad credentials
- `REASON_REVOKED` - CP revoked
- `REASON_OUT_OF_SERVICE` - CP out of service
- `REASON_EXPIRED_TOKEN` - Token expired
- `REASON_INVALID_TOKEN` - Invalid token
- `REASON_TOKEN_VERSION_MISMATCH` - Token version mismatch

### Incident Types
- `INCIDENT_BRUTE_FORCE` - Brute force attack
- `INCIDENT_UNAUTHORIZED_ADMIN` - Unauthorized admin access
- `INCIDENT_TAMPERING` - Tampering detected

## Severity Levels
- `INFO` - Informational
- `WARN` - Warning
- `ERROR` - Error
- `CRITICAL` - Critical security event

## Create Request Context (Non-HTTP)

```python
ctx = RequestContext(
    request_id="batch-job-123",
    ip="system",
    endpoint="/internal/operation",
    http_method="INTERNAL"
)
```

## Configuration

### Brute Force Thresholds

In `evcharging/common/audit_service.py`:

```python
BRUTE_FORCE_THRESHOLD = 5        # failures
BRUTE_FORCE_WINDOW_MINUTES = 10  # time window
```

### Trust Proxy Headers

Environment variable:

```bash
export TRUST_PROXY_HEADERS=true
```

## SQL Queries (Direct)

### Last 10 events

```sql
SELECT date_time, who, action, description
FROM audit_events
ORDER BY date_time DESC
LIMIT 10;
```

### Count by action

```sql
SELECT action, COUNT(*) as count
FROM audit_events
GROUP BY action
ORDER BY count DESC;
```

### Failed auths in last hour

```sql
SELECT *
FROM audit_events
WHERE action = 'AUTH_FAIL'
  AND date_time >= datetime('now', '-1 hour')
ORDER BY date_time DESC;
```

### All incidents

```sql
SELECT date_time, who, ip, description
FROM audit_events
WHERE action = 'INCIDENT'
ORDER BY date_time DESC;
```

### Events for specific CP

```sql
SELECT date_time, action, description, ip
FROM audit_events
WHERE who = 'CP-001'
ORDER BY date_time DESC
LIMIT 50;
```

## Testing

### Run All Tests

```bash
pytest evcharging/tests/test_audit_system.py -v
```

### Run Specific Test Class

```bash
pytest evcharging/tests/test_audit_system.py::TestAuditService -v
```

### Run with Coverage

```bash
pytest evcharging/tests/test_audit_system.py \
  --cov=evcharging.common.audit_service \
  --cov-report=term-missing
```

## Monitoring Script Template

```python
#!/usr/bin/env python3
from evcharging.common.database import AuditDB
from datetime import datetime, timedelta

audit_db = AuditDB("ev_charging.db")

# Last hour
start_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()

# Check incidents
incidents = audit_db.query_events(
    action="INCIDENT",
    start_time=start_time
)

if incidents:
    print(f"🚨 {len(incidents)} incident(s)")
    for inc in incidents:
        print(f"  {inc['date_time']}: {inc['description']}")
else:
    print("✅ No incidents")

# Check auth failures
failures = audit_db.query_events(
    action="AUTH_FAIL",
    start_time=start_time
)
print(f"ℹ️  {len(failures)} auth failures in last hour")
```

## Common Patterns

### Audit Wrapper for Functions

```python
def with_audit(func):
    """Decorator to add audit logging to functions."""
    def wrapper(*args, **kwargs):
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            ip="internal",
            endpoint=func.__name__,
            http_method="FUNCTION"
        )
        audit = get_audit_service()
        
        try:
            result = func(*args, **kwargs)
            audit.auth_success("system", ctx)
            return result
        except Exception as e:
            audit.error(ctx, type(e).__name__, str(e)[:200])
            raise
    
    return wrapper
```

### Batch Query with Aggregation

```python
def get_summary_stats(hours=24):
    """Get audit summary for last N hours."""
    audit_db = AuditDB("ev_charging.db")
    start = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    
    events = audit_db.query_events(start_time=start, limit=10000)
    
    from collections import Counter
    
    return {
        "total_events": len(events),
        "by_action": dict(Counter(e['action'] for e in events)),
        "by_severity": dict(Counter(e['severity'] for e in events)),
        "unique_cps": len(set(e['who'] for e in events)),
        "unique_ips": len(set(e['ip'] for e in events))
    }
```

## Files Reference

- **Database**: `evcharging/common/database.py` (AuditDB class)
- **Service**: `evcharging/common/audit_service.py` (AuditService class)
- **Middleware**: `evcharging/common/audit_middleware.py`
- **Integration**: `evcharging/apps/ev_central/security_api.py`
- **Tests**: `evcharging/tests/test_audit_system.py`
- **Docs**: `AUDIT_SYSTEM_README.md`, `AUDIT_MIGRATION_GUIDE.md`

## Support

See full documentation in:
- `AUDIT_SYSTEM_README.md` - Complete system overview
- `AUDIT_MIGRATION_GUIDE.md` - Migration and setup guide
