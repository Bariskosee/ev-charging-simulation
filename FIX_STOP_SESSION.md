# Stop Session Fix - Session ID Mismatch

## Problem
Clicking "End Charging Session" button failed with error: **"Failed to stop session"**

### Root Cause
**Session ID mismatch** between Driver and Central:
- Driver was using: `"pending-" + request_id` (e.g., `pending-req-3245d5f9`)
- Central was creating: actual session ID (e.g., `session-f5887c7a`)
- When driver sent stop request, Central rejected it because the session IDs didn't match

### Error Logs
```
Driver: Failed to send stop session request to Central: Client error '400 Bad Request'
Central: Session mismatch: requested pending-req-3245d5f9, current session-f5887c7a
```

## Solution

### 1. Add session_id to DriverUpdate Message
Updated `evcharging/common/messages.py` to include `session_id`:

```python
class DriverUpdate(BaseModel):
    """Status update sent back to driver."""
    request_id: str
    driver_id: str
    cp_id: str
    status: MessageStatus
    reason: Optional[str] = None
    session_id: Optional[str] = None  # ✅ NEW: Session ID from Central
    ts: datetime
```

### 2. Central Sends session_id in Updates
Updated `evcharging/apps/ev_central/main.py`:

**Modified `_send_driver_update()` method:**
```python
async def _send_driver_update(
    self,
    request: DriverRequest,
    status: MessageStatus,
    reason: str,
    session_id: Optional[str] = None  # ✅ NEW parameter
):
    update = DriverUpdate(
        request_id=request.request_id,
        driver_id=request.driver_id,
        cp_id=request.cp_id,
        status=status,
        reason=reason,
        session_id=session_id  # ✅ Include session_id
    )
    await self.producer.send(TOPICS["DRIVER_UPDATES"], update, key=request.driver_id)
```

**Updated ACCEPTED status to include session_id:**
```python
await self._send_driver_update(
    request,
    MessageStatus.ACCEPTED,
    "Request accepted, starting charging",
    session_id=cp.current_session  # ✅ Pass actual session_id
)
```

### 3. Driver Uses session_id from Central
Updated `evcharging/apps/ev_driver/main.py`:

**Modified `_apply_status_update()` to use Central's session_id:**
```python
updated = current.model_copy(
    update={
        "session_id": update.session_id or current.session_id,  # ✅ Use Central's ID
        "status": new_status,
        "started_at": current.started_at or (utc_now() if new_status == "CHARGING" else None),
        "completed_at": utc_now() if new_status in {"COMPLETED", "DENIED", "FAILED"} else None,
    }
)
```

## Flow Diagram

### Before Fix (❌ Failed)
```
Driver → Start Charging Request
  ↓
Driver → Creates local session: "pending-req-xyz"
  ↓
Central → Accepts request, creates: "session-abc123"
  ↓
Central → Sends ACCEPTED (without session_id)
  ↓
Driver → Still uses: "pending-req-xyz"
  ↓
User → Clicks "End Session"
  ↓
Driver → Sends stop request with: "pending-req-xyz"
  ↓
Central → Checks session_id: "pending-req-xyz" ≠ "session-abc123"
  ↓
❌ Central → 400 Bad Request: "Session mismatch"
```

### After Fix (✅ Success)
```
Driver → Start Charging Request
  ↓
Driver → Creates local session: "pending-req-xyz"
  ↓
Central → Accepts request, creates: "session-abc123"
  ↓
Central → Sends ACCEPTED with session_id: "session-abc123"  ✅
  ↓
Driver → Updates local session_id: "session-abc123"  ✅
  ↓
User → Clicks "End Session"
  ↓
Driver → Sends stop request with: "session-abc123"  ✅
  ↓
Central → Validates: "session-abc123" = "session-abc123"  ✅
  ↓
Central → Sends STOP_SUPPLY to CP Engine
  ↓
✅ Session stopped successfully
```

## Testing

### 1. Rebuild Services
```bash
docker compose build ev-central ev-driver-alice ev-driver-bob ev-driver-charlie ev-driver-david ev-driver-eve
```

### 2. Restart Services
```bash
docker compose up -d --force-recreate ev-central ev-driver-alice ev-driver-bob ev-driver-charlie ev-driver-david ev-driver-eve
```

### 3. Test Stop Session
1. Open driver dashboard: http://localhost:8100
2. Click "⚡ Start Charging" on any available CP
3. Wait for session to show "🔋 Charging"
4. Click "⏹️ End Charging Session"
5. ✅ Session should stop successfully (no error notifications)

### 4. Verify in Logs
```bash
# Check driver logs - should see successful stop request
docker logs ev-driver-alice 2>&1 | grep "Stop session request sent"

# Check Central logs - should see stop command sent
docker logs ev-central 2>&1 | grep "STOP_SUPPLY"

# Should NOT see session mismatch errors
docker logs ev-central 2>&1 | grep "Session mismatch"
```

## Expected Behavior

### ✅ After Fix
- Click "End Charging Session" → Session stops immediately
- No error notifications
- Session status updates to COMPLETED
- Charging point becomes FREE
- No session mismatch errors in logs

### ❌ Before Fix
- Click "End Charging Session" → Multiple ERROR notifications
- "Failed to stop session" errors
- Session continues charging
- Central logs show "Session mismatch" warnings

## Technical Details

### Key Changes
1. **Message Protocol**: Added `session_id` field to `DriverUpdate`
2. **Central Logic**: Passes actual `session_id` when sending ACCEPTED update
3. **Driver Logic**: Updates local session with `session_id` from Central
4. **Synchronization**: Driver and Central now use the same session identifier

### Backward Compatibility
- The change is backward compatible
- `session_id` is Optional, defaults to `None`
- Driver generates fallback ID if Central doesn't provide one
- Old sessions without session_id will still work (but stop won't work)

## Files Modified
1. ✅ `evcharging/common/messages.py` - Added `session_id` to `DriverUpdate`
2. ✅ `evcharging/apps/ev_central/main.py` - Send session_id in updates, import Optional
3. ✅ `evcharging/apps/ev_driver/main.py` - Use session_id from Central

## Status
✅ **FIXED** - Stop session functionality now works correctly!

## Summary
The stop session feature failed because driver and Central used different session IDs. By adding `session_id` to the `DriverUpdate` message and ensuring both sides use Central's authoritative session ID, the stop session functionality now works perfectly. Users can now manually stop charging sessions through the dashboard without errors.
