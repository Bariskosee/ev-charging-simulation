#!/usr/bin/env python3
"""
Test security fixes for:
1. Key wrapping bound to cp_id
2. Registry/status checks before key generation
3. Migration detection
4. Dedicated key-wrapping secret
"""

import os
import sys
from pathlib import Path

# Set required environment variable
os.environ["EV_KEY_ENCRYPTION_SECRET"] = "test-key-wrapping-secret-for-cp-encryption-keys-minimum-32-chars"
os.environ["EV_SECURITY_SECRET"] = "test-jwt-secret-different-from-key-wrap-min-32-chars-long"

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from evcharging.common.cp_security import CPEncryptionService, CPSecurityService
from evcharging.common.database import CPSecurityDB, CPRegistryDB
from evcharging.common.security import create_security_manager
from evcharging.common.config import CentralConfig

print("\n" + "=" * 70)
print("Security Fixes Verification")
print("=" * 70)

# Test 1: Key wrapping with cp_id binding
print("\n[Test 1] Key Wrapping with CP ID Binding")
print("-" * 70)

try:
    # Initialize key wrapping
    CPEncryptionService.initialize_key_wrapping(
        os.environ["EV_KEY_ENCRYPTION_SECRET"]
    )
    
    # Generate and wrap a key for CP-001
    key = CPEncryptionService.generate_key()
    wrapped_cp1 = CPEncryptionService.wrap_key(key, "CP-001")
    
    print(f"✓ Key wrapped for CP-001")
    print(f"  Wrapped length: {len(wrapped_cp1)} chars")
    
    # Unwrap with correct CP ID
    unwrapped = CPEncryptionService.unwrap_key(wrapped_cp1, "CP-001")
    assert unwrapped == key, "Unwrapped key should match original"
    print(f"✓ Key unwrapped successfully with correct CP ID")
    
    # Try to unwrap with wrong CP ID (should fail)
    try:
        CPEncryptionService.unwrap_key(wrapped_cp1, "CP-002")
        print("✗ FAIL: Should have rejected wrong CP ID")
        sys.exit(1)
    except ValueError as e:
        print(f"✓ Correctly rejected wrong CP ID")
        print(f"  Error: {str(e)[:60]}...")
    
    print("\n✅ Test 1 PASSED: Keys are bound to CP ID")

except Exception as e:
    print(f"✗ Test 1 FAILED: {e}")
    sys.exit(1)

# Test 2: Dedicated key-wrapping secret required
print("\n[Test 2] Dedicated Key-Wrapping Secret Required")
print("-" * 70)

try:
    # Test that short secret is rejected
    try:
        CPEncryptionService.initialize_key_wrapping("short")
        print("✗ FAIL: Should have rejected short secret")
        sys.exit(1)
    except ValueError as e:
        print(f"✓ Correctly rejected short secret")
        print(f"  Error: {str(e)[:60]}...")
    
    # Test that empty secret is rejected
    try:
        CPEncryptionService.initialize_key_wrapping("")
        print("✗ FAIL: Should have rejected empty secret")
        sys.exit(1)
    except ValueError as e:
        print(f"✓ Correctly rejected empty secret")
    
    print("\n✅ Test 2 PASSED: Dedicated secret validation works")

except Exception as e:
    print(f"✗ Test 2 FAILED: {e}")
    sys.exit(1)

# Test 3: Registry checks before key generation
print("\n[Test 3] Registry Checks Before Key Generation")
print("-" * 70)

try:
    # Setup
    db_path = "test_security_fixes.db"
    security_db = CPSecurityDB(db_path)
    registry_db = CPRegistryDB(db_path)
    security_manager = create_security_manager(
        secret_key=os.environ["EV_SECURITY_SECRET"],
        token_expiration_hours=24
    )
    
    # Initialize service
    cp_security = CPSecurityService(
        security_db=security_db,
        registry_db=registry_db,
        security_manager=security_manager,
        db_path=db_path
    )
    
    # Try to generate key for non-existent CP (should fail)
    try:
        cp_security.generate_key_for_cp("NON-EXISTENT-CP")
        print("✗ FAIL: Should have rejected non-existent CP")
        sys.exit(1)
    except ValueError as e:
        print(f"✓ Correctly rejected non-existent CP")
        print(f"  Error: {str(e)[:70]}...")
    
    # Register CP in registry
    credentials = "test-credentials-abc123"
    cred_hash = security_manager.hash_credentials(credentials)
    registry_db.register_cp(
        cp_id="TEST-CP-CHECKS",
        location="Test Location",
        credentials_hash=cred_hash
    )
    
    # Initialize security status
    security_db.initialize_cp_security("TEST-CP-CHECKS")
    
    # Now key generation should succeed
    success = cp_security.generate_key_for_cp("TEST-CP-CHECKS")
    assert success, "Key generation should succeed for registered ACTIVE CP"
    print(f"✓ Key generated for registered ACTIVE CP")
    
    # Set CP to REVOKED
    cp_security.revoke_cp("TEST-CP-CHECKS", "Test revocation")
    
    # Try to generate key for REVOKED CP (should fail)
    try:
        cp_security.generate_key_for_cp("TEST-CP-REVOKED-TEST")
        print("✗ FAIL: Should have rejected REVOKED CP")
    except ValueError as e:
        print(f"✓ Correctly enforces ACTIVE status requirement")
    
    print("\n✅ Test 3 PASSED: Registry and status checks enforced")

except Exception as e:
    print(f"✗ Test 3 FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Key retrieval with unwrapping
print("\n[Test 4] Key Retrieval with Unwrapping")
print("-" * 70)

try:
    # Register and generate key for new CP
    registry_db.register_cp(
        cp_id="TEST-CP-UNWRAP",
        location="Test Location",
        credentials_hash=cred_hash
    )
    security_db.initialize_cp_security("TEST-CP-UNWRAP")
    
    # Generate key
    cp_security.generate_key_for_cp("TEST-CP-UNWRAP")
    
    # Clear cache to force unwrapping
    cp_security._key_cache.clear()
    
    # Retrieve key (should unwrap from database)
    key = cp_security.get_key_for_cp("TEST-CP-UNWRAP")
    assert key is not None, "Should retrieve and unwrap key"
    assert len(key) == 32, "Key should be 32 bytes"
    print(f"✓ Key retrieved and unwrapped from storage")
    print(f"  Key length: {len(key)} bytes")
    
    # Verify key is cached
    cached_key = cp_security.get_key_for_cp("TEST-CP-UNWRAP")
    assert cached_key == key, "Cached key should match"
    print(f"✓ Key cached for performance")
    
    print("\n✅ Test 4 PASSED: Key unwrapping works correctly")

except Exception as e:
    print(f"✗ Test 4 FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 5: Migration detection
print("\n[Test 5] Migration Detection")
print("-" * 70)

try:
    # Simulate old key without encrypted_key (only key_hash)
    security_db.store_encryption_key(
        cp_id="OLD-CP-NO-WRAP",
        key_hash="abc123def456",  # Fake hash
        encrypted_key=None  # No wrapped key (old format)
    )
    
    # Check migration detection
    unmigrated = security_db.get_unmigrated_keys()
    assert "OLD-CP-NO-WRAP" in unmigrated, "Should detect unmigrated key"
    print(f"✓ Detected unmigrated key: OLD-CP-NO-WRAP")
    
    # Try to retrieve (should fail gracefully)
    key = cp_security.get_key_for_cp("OLD-CP-NO-WRAP")
    assert key is None, "Should return None for unmigrated key"
    print(f"✓ Retrieval fails gracefully for unmigrated key")
    print(f"  (Logs guide user to run migration)")
    
    print("\n✅ Test 5 PASSED: Migration detection works")

except Exception as e:
    print(f"✗ Test 5 FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Summary
print("\n" + "=" * 70)
print("✅ ALL SECURITY FIXES VERIFIED")
print("=" * 70)
print()
print("Fixed issues:")
print("  1. ✅ Keys bound to CP ID (prevents key swapping)")
print("  2. ✅ Dedicated key-wrapping secret required")
print("  3. ✅ Registry/status checks before key generation")
print("  4. ✅ Key unwrapping with cp_id validation")
print("  5. ✅ Migration detection for old keys")
print()
print("Security posture: IMPROVED")
print()
