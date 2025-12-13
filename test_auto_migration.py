#!/usr/bin/env python3
"""
Test automatic key migration on service startup.
"""

import os
import sys
from pathlib import Path

# Set required environment variables
os.environ["EV_KEY_ENCRYPTION_SECRET"] = "test-key-wrapping-secret-for-auto-migration-min-32-chars"
os.environ["EV_SECURITY_SECRET"] = "test-jwt-secret-different-from-key-wrap-min-32-chars-long"

sys.path.insert(0, str(Path(__file__).parent))

from evcharging.common.cp_security import CPSecurityService
from evcharging.common.database import CPSecurityDB, CPRegistryDB
from evcharging.common.security import create_security_manager

print("\n" + "=" * 70)
print("Auto-Migration Test")
print("=" * 70)

# Setup
db_path = "test_auto_migration.db"
security_db = CPSecurityDB(db_path)
registry_db = CPRegistryDB(db_path)
security_manager = create_security_manager(
    secret_key=os.environ["EV_SECURITY_SECRET"],
    token_expiration_hours=24
)

# Register 3 CPs
print("\n[Setup] Creating legacy keys...")
print("-" * 70)

for i in range(1, 4):
    cp_id = f"LEGACY-CP-{i:03d}"
    
    # Register in registry
    credentials = f"credentials-{i}"
    cred_hash = security_manager.hash_credentials(credentials)
    registry_db.register_cp(
        cp_id=cp_id,
        location=f"Location {i}",
        credentials_hash=cred_hash
    )
    
    # Initialize security status
    security_db.initialize_cp_security(cp_id)
    
    # Create legacy key (only key_hash, no encrypted_key)
    security_db.store_encryption_key(
        cp_id=cp_id,
        key_hash=f"legacy_hash_{i}",
        encrypted_key=None  # No wrapped key - legacy format
    )
    
    print(f"✓ Created legacy key for {cp_id}")

# Verify unmigrated keys exist
unmigrated = security_db.get_unmigrated_keys()
print(f"\n✓ Found {len(unmigrated)} unmigrated keys: {unmigrated}")

# Now initialize service - should auto-migrate
print("\n[Test] Initializing service with auto-migration...")
print("-" * 70)

cp_security = CPSecurityService(
    security_db=security_db,
    registry_db=registry_db,
    security_manager=security_manager,
    db_path=db_path
)

# Check if migration completed
print("\n[Verification] Checking migration results...")
print("-" * 70)

unmigrated_after = security_db.get_unmigrated_keys()
print(f"Unmigrated keys after startup: {len(unmigrated_after)}")

if len(unmigrated_after) == 0:
    print("✓ All legacy keys successfully migrated")
else:
    print(f"✗ Still have unmigrated keys: {unmigrated_after}")
    sys.exit(1)

# Verify each CP can now encrypt/decrypt
print("\n[Verification] Testing encryption with migrated keys...")
print("-" * 70)

for i in range(1, 4):
    cp_id = f"LEGACY-CP-{i:03d}"
    
    # Get key (should work now)
    key = cp_security.get_key_for_cp(cp_id)
    if not key:
        print(f"✗ Failed to get key for {cp_id}")
        sys.exit(1)
    
    # Test encryption
    test_payload = {"test": f"data_{i}"}
    encrypted = cp_security.encrypt_for_cp(cp_id, test_payload)
    if not encrypted:
        print(f"✗ Failed to encrypt for {cp_id}")
        sys.exit(1)
    
    # Test decryption
    decrypted = cp_security.decrypt_from_cp(cp_id, encrypted)
    if decrypted != test_payload:
        print(f"✗ Decryption mismatch for {cp_id}")
        sys.exit(1)
    
    print(f"✓ {cp_id}: Encryption/decryption working")

print("\n" + "=" * 70)
print("✅ AUTO-MIGRATION TEST PASSED")
print("=" * 70)
print()
print("Results:")
print(f"  - {len(unmigrated)} legacy keys detected on startup")
print(f"  - All keys automatically migrated to wrapped format")
print(f"  - All CPs can encrypt/decrypt immediately")
print()
print("Operational benefit:")
print("  - No manual intervention required after upgrade")
print("  - CPs ready for encrypted communication on startup")
print("  - Migration logged for audit trail")
print()
