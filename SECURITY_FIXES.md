# Security Fixes - EV_Central Security Extension

**Date:** December 14, 2025  
**Status:** ✅ ALL FIXES IMPLEMENTED AND VERIFIED

## Overview

Four critical security issues in the EV_Central Security Extension have been identified and fixed. All fixes have been implemented, tested, and verified.

---

## Issues Fixed

### 1. ✅ Key Wrapping Not Bound to CP Identifier

**Issue:** Wrapped encryption keys were not bound to the target `cp_id`. A ciphertext copied from another CP would decrypt successfully, breaking per-CP isolation guarantees.

**Security Impact:** HIGH - Malicious actor could swap stored keys between CPs

**Fix Implemented:**
- Added `cp_id` as AES-GCM Associated Authenticated Data (AAD) when encrypting keys
- Decryption validates that the provided `cp_id` matches the AAD
- Key swapping between CPs is now cryptographically prevented

**Code Changes:**
- `CPEncryptionService.wrap_key()`: Uses `cp_id` as AAD in AES-GCM encryption
- `CPEncryptionService.unwrap_key()`: Validates `cp_id` matches AAD during decryption

**Verification:**
```python
# Test shows wrapped key for CP-001 cannot be unwrapped for CP-002
wrapped = CPEncryptionService.wrap_key(key, "CP-001")
CPEncryptionService.unwrap_key(wrapped, "CP-002")  # Raises ValueError
```

---

### 2. ✅ Key Generation Bypasses CP Registry/State Checks

**Issue:** `generate_key_for_cp()` created keys without confirming the CP exists in the registry or is currently ACTIVE. This allowed key creation for revoked/out-of-service or unknown CPs.

**Security Impact:** HIGH - Undermines status model and access control

**Fix Implemented:**
- Added mandatory registry existence check before key generation
- Added security status validation (must be ACTIVE)
- Clear error messages guide administrators
- Added `force` parameter to `reset_key_for_cp()` for migration scenarios

**Code Changes:**
- `generate_key_for_cp()`: Now validates CP exists in registry and status is ACTIVE
- `reset_key_for_cp(force=False)`: Enforces checks unless force=True for migration
- Raises `ValueError` with descriptive message if validation fails

**Verification:**
```python
# Attempting to generate key for non-existent CP fails
cp_security.generate_key_for_cp("NON-EXISTENT")  
# Raises: "CP must be registered in EV_Registry before key generation"

# Attempting to generate key for REVOKED CP fails  
cp_security.generate_key_for_cp("REVOKED-CP")
# Raises: "Only ACTIVE CPs can have keys generated"
```

---

### 3. ✅ Missing Migration/Backfill Path for Existing Keys

**Issue:** New `encrypted_key` column was added, but existing rows with only `key_hash` became unusable. Retrieval requires ciphertext, so previously provisioned CPs lost encryption capability.

**Security Impact:** MEDIUM - Operational disruption for existing deployments

**Fix Implemented:**
- Added `get_unmigrated_keys()` method to detect keys needing migration
- Added migration detection during service initialization
- Clear warning logs guide administrators to fix unmigrated keys
- `reset_key_for_cp(force=True)` can re-wrap keys even for non-ACTIVE CPs
- `get_key_for_cp()` fails gracefully with actionable error message

**Code Changes:**
- `CPSecurityDB.get_unmigrated_keys()`: Finds CPs with `key_hash` but no `encrypted_key`
- `CPSecurityService._check_key_migration_needed()`: Called during initialization
- `get_key_for_cp()`: Returns None with guidance if key needs migration

**Verification:**
```python
# Migration detection finds unmigrated keys
unmigrated = security_db.get_unmigrated_keys()
# Returns: ["OLD-CP-NO-WRAP"]

# Attempting to use unmigrated key logs clear guidance
key = cp_security.get_key_for_cp("OLD-CP-NO-WRAP")
# Logs: "Call reset_key_for_cp(cp_id, force=True) to re-wrap the key"
```

**Migration Steps:**
```bash
# For each unmigrated CP:
1. Identify CPs: Check logs for "keys needing migration" warning
2. Backup database before migration
3. Run migration:
   python -c "
   from evcharging.common.cp_security import CPSecurityService
   # Initialize service
   cp_security.reset_key_for_cp('CP-ID', force=True)
   "
4. Verify: Check logs for "Reset encryption key for CP"
```

---

### 4. ✅ Key-Wrapping Secret Falls Back to JWT Secret

**Issue:** When `EV_KEY_ENCRYPTION_SECRET` was unset, the service silently reused the JWT signing secret for key wrapping. This coupled unrelated trust domains and increased blast radius if one secret was exposed.

**Security Impact:** MEDIUM - Secret reuse violates security best practices

**Fix Implemented:**
- Service now fails fast during startup if `EV_KEY_ENCRYPTION_SECRET` is missing
- Added validation: secret must be minimum 32 characters
- Clear error message guides administrators to set distinct secrets
- `initialize_key_wrapping()` validates secret before use

**Code Changes:**
- `CPSecurityService.__init__()`: Checks for `EV_KEY_ENCRYPTION_SECRET` env var
- `CPEncryptionService.initialize_key_wrapping()`: Validates secret length
- Raises `ValueError` with setup instructions if misconfigured

**Verification:**
```python
# Missing secret causes immediate failure
os.environ.pop("EV_KEY_ENCRYPTION_SECRET")
CPSecurityService(...)  # Raises ValueError with instructions

# Short secret is rejected
CPEncryptionService.initialize_key_wrapping("short")
# Raises: "Minimum 32 characters required for security"
```

**Configuration Required:**
```bash
# Set distinct secrets (NEVER reuse JWT secret)
export EV_SECURITY_SECRET="jwt-signing-secret-min-32-chars-long"
export EV_KEY_ENCRYPTION_SECRET="key-wrapping-secret-different-min-32-chars"

# Generate secure secrets:
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## Implementation Summary

### Files Modified

1. **evcharging/common/cp_security.py**
   - Added `_wrapping_key` class variable to `CPEncryptionService`
   - Added `initialize_key_wrapping()` with validation
   - Added `wrap_key()` with cp_id binding
   - Added `unwrap_key()` with cp_id validation
   - Updated `__init__()` to require `EV_KEY_ENCRYPTION_SECRET`
   - Added `_check_key_migration_needed()` for migration detection
   - Updated `generate_key_for_cp()` with registry/status checks
   - Updated `reset_key_for_cp()` with force parameter
   - Updated `get_key_for_cp()` to unwrap keys with validation

2. **evcharging/common/database.py**
   - Added `encrypted_key` column to `cp_encryption_keys` table schema
   - Updated `store_encryption_key()` to accept `encrypted_key` parameter
   - Updated `get_key_info()` to return `encrypted_key` and `key_hash`
   - Added `get_unmigrated_keys()` to detect migration needs
   - Added `set_registration_status()` for force migration support

3. **Test Files Created**
   - `test_security_fixes.py`: Comprehensive verification of all fixes

### Database Schema Changes

```sql
-- Added column to cp_encryption_keys table
ALTER TABLE cp_encryption_keys ADD COLUMN encrypted_key TEXT;

-- New databases automatically include this column
-- Existing databases need migration (see Migration Steps above)
```

---

## Testing Results

All tests passed successfully:

```
✅ Test 1 PASSED: Keys are bound to CP ID
✅ Test 2 PASSED: Dedicated secret validation works
✅ Test 3 PASSED: Registry and status checks enforced
✅ Test 4 PASSED: Key unwrapping works correctly
✅ Test 5 PASSED: Migration detection works
```

**Test Coverage:**
- Key wrapping with cp_id binding and rejection of wrong CP
- Dedicated secret validation (length, empty checks)
- Registry existence checks before key generation
- Security status enforcement (ACTIVE required)
- Key unwrapping with integrity validation
- Migration detection for old keys
- Graceful failure with actionable guidance

---

## Deployment Guide

### Prerequisites

1. **Set Environment Variables (REQUIRED)**
   ```bash
   # Generate two DISTINCT secure secrets
   export EV_SECURITY_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   export EV_KEY_ENCRYPTION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   
   # Verify they are different
   echo "JWT Secret: $EV_SECURITY_SECRET"
   echo "Key Wrap Secret: $EV_KEY_ENCRYPTION_SECRET"
   ```

2. **Backup Database**
   ```bash
   cp ev_charging.db ev_charging.db.backup
   ```

### Fresh Installation

For new deployments, no migration is needed. Just ensure environment variables are set before starting EV_Central:

```bash
export EV_KEY_ENCRYPTION_SECRET="your-secure-secret-min-32-chars"
python -m evcharging.apps.ev_central.main
```

### Existing Installation Migration

If upgrading from a previous version:

1. **Stop EV_Central**
   ```bash
   # Stop the service
   docker compose down ev-central
   ```

2. **Set Environment Variable**
   ```bash
   # Add to docker-compose.yml or .env file
   EV_KEY_ENCRYPTION_SECRET=your-secure-secret-min-32-chars
   ```

3. **Update Database Schema** (if needed)
   ```python
   # Run migration script
   from evcharging.common.database import CPSecurityDB
   db = CPSecurityDB("ev_charging.db")
   # Schema is auto-updated on next connection
   ```

4. **Start EV_Central**
   ```bash
   docker compose up -d ev-central
   ```

5. **Check Logs for Migration Warnings**
   ```bash
   docker compose logs ev-central | grep "migration"
   ```

6. **Migrate Keys (if needed)**
   ```python
   # For each CP that needs migration:
   from evcharging.common.cp_security import CPSecurityService
   # ... initialize service ...
   cp_security.reset_key_for_cp('CP-ID', force=True)
   ```

---

## Security Posture

### Before Fixes
- ❌ Keys could be swapped between CPs
- ❌ Keys created for revoked/unknown CPs
- ❌ No migration path for existing keys
- ❌ Silent fallback to JWT secret

### After Fixes
- ✅ Keys cryptographically bound to CP ID
- ✅ Registry and status validated before key operations
- ✅ Migration detection with clear guidance
- ✅ Dedicated secrets enforced with validation

**Security Rating:** IMPROVED from MEDIUM to HIGH

---

## API Changes

### Breaking Changes

1. **Service Initialization**
   - Now REQUIRES `EV_KEY_ENCRYPTION_SECRET` environment variable
   - Will fail fast with clear error if missing

2. **Key Generation**
   - Now enforces CP registry existence
   - Now enforces ACTIVE security status
   - Raises `ValueError` instead of returning False for validation failures

### New Features

1. **Migration Support**
   - `reset_key_for_cp(cp_id, force=True)`: Bypass checks for migration
   - `get_unmigrated_keys()`: Detect keys needing migration
   - Migration warnings during service initialization

2. **Enhanced Validation**
   - Key unwrapping validates CP ID binding
   - Integrity checks on unwrapped keys
   - Clear error messages for all failure modes

---

## Backward Compatibility

### Compatible
- Existing authentication flows unchanged
- Existing status management unchanged
- Existing API endpoints unchanged

### Requires Action
- **Environment Variable:** Must set `EV_KEY_ENCRYPTION_SECRET`
- **Database Schema:** Auto-migrated on first connection
- **Existing Keys:** May need migration (with clear guidance in logs)

---

## Monitoring & Observability

### Key Metrics to Monitor

1. **Migration Status**
   - Check logs for "keys needing migration" warnings
   - Track count of unmigrated keys over time

2. **Key Operations**
   - Monitor key generation failures (indicates misconfigured CPs)
   - Track key unwrapping failures (indicates corrupted keys or wrong CP ID)

3. **Authentication**
   - Monitor authentication failures for revoked CPs
   - Track status changes (ACTIVE → OUT_OF_SERVICE → REVOKED)

### Log Messages to Watch

```
INFO  - Key wrapping initialized with dedicated secret
WARN  - Found X CP(s) with keys needing migration: [...]
ERROR - Key generation validation failed: CP not found in registry
ERROR - Key unwrapping failed: cp_id may not match
```

---

## References

- Original Implementation: [EV_CENTRAL_SECURITY_IMPLEMENTATION.md](EV_CENTRAL_SECURITY_IMPLEMENTATION.md)
- Test Results: [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md)
- API Reference: [EV_CENTRAL_SECURITY_QUICKREF.md](EV_CENTRAL_SECURITY_QUICKREF.md)

---

## Support

For issues related to these security fixes:

1. Check logs for detailed error messages
2. Verify `EV_KEY_ENCRYPTION_SECRET` is set correctly
3. Review [test_security_fixes.py](test_security_fixes.py) for examples
4. See migration steps above for key migration

---

**Status:** ✅ PRODUCTION READY  
**Test Date:** December 14, 2025  
**All Security Fixes Verified:** ✅
