#!/usr/bin/env python3
"""
EV_Central Security Extensions - Usage Examples

Demonstrates the security features:
- CP authentication
- Key management
- Status management
- Encrypted communication
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evcharging.common.database import CPSecurityDB, CPRegistryDB
from evcharging.common.security import create_security_manager
from evcharging.common.cp_security import (
    CPSecurityService,
    CPSecurityStatus,
    CPEncryptionService
)


async def example_1_authentication():
    """Example 1: CP Authentication"""
    print("\n" + "="*60)
    print("Example 1: CP Authentication")
    print("="*60)
    
    # Initialize components
    db_path = "example_security.db"
    security_db = CPSecurityDB(db_path)
    registry_db = CPRegistryDB(db_path)
    security_manager = create_security_manager(
        secret_key="example-secret-key-minimum-32-chars!!!",
        token_expiration_hours=24
    )
    
    cp_security = CPSecurityService(
        security_db=security_db,
        registry_db=registry_db,
        security_manager=security_manager,
        db_path=db_path
    )
    
    # Simulate CP registration (normally done by EV_Registry)
    cp_id = "CP-EXAMPLE-001"
    credentials = "example-credentials-secret-abc123"
    credentials_hash = security_manager.hash_credentials(credentials)
    
    registry_db.register_cp(
        cp_id=cp_id,
        location="Example City",
        credentials_hash=credentials_hash
    )
    print(f"✓ CP {cp_id} registered in registry")
    
    # Initialize security
    security_db.initialize_cp_security(cp_id)
    cp_security.generate_key_for_cp(cp_id)
    print(f"✓ Security initialized for {cp_id}")
    
    # Authenticate with correct credentials
    print(f"\n→ Authenticating {cp_id} with credentials...")
    auth_result = cp_security.authenticate_cp(cp_id, credentials)
    
    if auth_result.is_authorized():
        print(f"✓ Authentication successful!")
        print(f"  - Status: {auth_result.status.value}")
        print(f"  - Token: {auth_result.token[:50]}...")
    else:
        print(f"✗ Authentication failed: {auth_result.reason}")
    
    # Authenticate with wrong credentials
    print(f"\n→ Authenticating with wrong credentials...")
    auth_result = cp_security.authenticate_cp(cp_id, "wrong-credentials")
    
    if not auth_result.success:
        print(f"✓ Correctly rejected invalid credentials")
        print(f"  - Reason: {auth_result.reason}")
    
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


async def example_2_key_management():
    """Example 2: Encryption Key Management"""
    print("\n" + "="*60)
    print("Example 2: Encryption Key Management")
    print("="*60)
    
    # Initialize
    db_path = "example_keys.db"
    security_db = CPSecurityDB(db_path)
    registry_db = CPRegistryDB(db_path)
    security_manager = create_security_manager(
        secret_key="example-secret-key-minimum-32-chars!!!"
    )
    
    cp_security = CPSecurityService(
        security_db=security_db,
        registry_db=registry_db,
        security_manager=security_manager,
        db_path=db_path
    )
    
    cp_id = "CP-KEYS-001"
    
    # Generate key
    print(f"\n→ Generating encryption key for {cp_id}...")
    cp_security.generate_key_for_cp(cp_id)
    
    key_info = security_db.get_key_info(cp_id)
    print(f"✓ Key generated")
    print(f"  - Version: {key_info['key_version']}")
    print(f"  - Status: {key_info['status']}")
    print(f"  - Created: {key_info['key_created_at']}")
    
    # Get key
    key = cp_security.get_key_for_cp(cp_id)
    print(f"  - Key length: {len(key)} bytes")
    
    # Reset (rotate) key
    print(f"\n→ Resetting (rotating) key...")
    cp_security.reset_key_for_cp(cp_id)
    
    new_key_info = security_db.get_key_info(cp_id)
    print(f"✓ Key rotated")
    print(f"  - New version: {new_key_info['key_version']}")
    print(f"  - Rotated at: {new_key_info['key_rotated_at']}")
    
    # Revoke key
    print(f"\n→ Revoking key...")
    cp_security.revoke_key_for_cp(cp_id)
    
    revoked_info = security_db.get_key_info(cp_id)
    print(f"✓ Key revoked")
    print(f"  - Status: {revoked_info['status']}")
    
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


async def example_3_encryption():
    """Example 3: Payload Encryption"""
    print("\n" + "="*60)
    print("Example 3: Payload Encryption & Decryption")
    print("="*60)
    
    # Generate a test key
    key = CPEncryptionService.generate_key()
    print(f"✓ Generated 256-bit key ({len(key)} bytes)")
    
    # Original payload
    payload = {
        "command": "START_SUPPLY",
        "session_id": "sess-12345",
        "driver_id": "driver-abc",
        "timestamp": "2025-12-14T10:30:00Z"
    }
    print(f"\n→ Original payload:")
    print(f"  {payload}")
    
    # Encrypt
    import json
    payload_json = json.dumps(payload)
    encrypted = CPEncryptionService.encrypt_payload(payload_json, key)
    print(f"\n→ Encrypted (base64):")
    print(f"  {encrypted[:80]}...")
    print(f"  Length: {len(encrypted)} chars")
    
    # Decrypt
    decrypted_json = CPEncryptionService.decrypt_payload(encrypted, key)
    decrypted = json.loads(decrypted_json)
    print(f"\n→ Decrypted payload:")
    print(f"  {decrypted}")
    
    # Verify
    if payload == decrypted:
        print(f"\n✓ Encryption/decryption successful - payloads match!")
    else:
        print(f"\n✗ Error - payloads don't match")
    
    # Try with wrong key
    print(f"\n→ Attempting decryption with wrong key...")
    try:
        wrong_key = CPEncryptionService.generate_key()
        CPEncryptionService.decrypt_payload(encrypted, wrong_key)
        print(f"✗ ERROR: Should have failed!")
    except ValueError as e:
        print(f"✓ Correctly rejected wrong key: {e}")


async def example_4_status_management():
    """Example 4: CP Status Management"""
    print("\n" + "="*60)
    print("Example 4: CP Status Management")
    print("="*60)
    
    # Initialize
    db_path = "example_status.db"
    security_db = CPSecurityDB(db_path)
    registry_db = CPRegistryDB(db_path)
    security_manager = create_security_manager(
        secret_key="example-secret-key-minimum-32-chars!!!"
    )
    
    cp_security = CPSecurityService(
        security_db=security_db,
        registry_db=registry_db,
        security_manager=security_manager,
        db_path=db_path
    )
    
    cp_id = "CP-STATUS-001"
    
    # Initialize as ACTIVE
    print(f"\n→ Initializing {cp_id} as ACTIVE...")
    security_db.initialize_cp_security(cp_id)
    
    status = cp_security.get_security_status(cp_id)
    print(f"✓ Status: {status.value}")
    
    # Set OUT_OF_SERVICE
    print(f"\n→ Setting CP to OUT_OF_SERVICE...")
    cp_security.set_out_of_service(cp_id, reason="Scheduled maintenance")
    
    status = cp_security.get_security_status(cp_id)
    print(f"✓ Status: {status.value}")
    
    status_detail = security_db.get_cp_security_status(cp_id)
    print(f"  - Reason: {status_detail['out_of_service_reason']}")
    print(f"  - Since: {status_detail['out_of_service_at']}")
    
    # Restore to ACTIVE
    print(f"\n→ Restoring CP to ACTIVE...")
    cp_security.restore_to_active(cp_id)
    
    status = cp_security.get_security_status(cp_id)
    print(f"✓ Status: {status.value}")
    
    # REVOKE (permanent)
    print(f"\n→ REVOKING CP (permanent)...")
    cp_security.revoke_cp(cp_id, reason="Security violation detected")
    
    status = cp_security.get_security_status(cp_id)
    print(f"✓ Status: {status.value}")
    
    status_detail = security_db.get_cp_security_status(cp_id)
    print(f"  - Reason: {status_detail['revocation_reason']}")
    print(f"  - Revoked at: {status_detail['revoked_at']}")
    print(f"\n⚠ REVOKED status is permanent - CP cannot be restored")
    
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


async def example_5_integrated_flow():
    """Example 5: Complete Integrated Security Flow"""
    print("\n" + "="*60)
    print("Example 5: Complete Integrated Security Flow")
    print("="*60)
    
    # Initialize
    db_path = "example_integrated.db"
    security_db = CPSecurityDB(db_path)
    registry_db = CPRegistryDB(db_path)
    security_manager = create_security_manager(
        secret_key="example-secret-key-minimum-32-chars!!!"
    )
    
    cp_security = CPSecurityService(
        security_db=security_db,
        registry_db=registry_db,
        security_manager=security_manager,
        db_path=db_path
    )
    
    cp_id = "CP-INTEGRATED-001"
    credentials = "secure-credentials-xyz789"
    
    # Step 1: Register CP (via EV_Registry)
    print(f"\n[1] CP Registration (via EV_Registry)")
    credentials_hash = security_manager.hash_credentials(credentials)
    registry_db.register_cp(
        cp_id=cp_id,
        location="Integrated Test Location",
        credentials_hash=credentials_hash
    )
    print(f"    ✓ CP registered in EV_Registry")
    
    # Step 2: Initialize security in EV_Central
    print(f"\n[2] Security Initialization (EV_Central)")
    security_db.initialize_cp_security(cp_id)
    cp_security.generate_key_for_cp(cp_id)
    print(f"    ✓ Security status initialized: ACTIVE")
    print(f"    ✓ Encryption key generated")
    
    # Step 3: CP authenticates
    print(f"\n[3] CP Authentication")
    auth_result = cp_security.authenticate_cp(cp_id, credentials)
    if auth_result.is_authorized():
        print(f"    ✓ Authentication successful")
        print(f"    ✓ Token issued: {auth_result.token[:40]}...")
    
    # Step 4: Encrypt a command
    print(f"\n[4] Encrypt Command for CP")
    command = {
        "type": "START_SUPPLY",
        "session_id": "sess-abc-123",
        "driver_id": "driver-001"
    }
    encrypted_command = cp_security.encrypt_for_cp(cp_id, command)
    print(f"    ✓ Command encrypted: {encrypted_command[:60]}...")
    
    # Step 5: Decrypt a response
    print(f"\n[5] Decrypt Response from CP")
    response = {
        "status": "SUPPLYING",
        "kw": 22.5,
        "kwh": 5.3,
        "session_id": "sess-abc-123"
    }
    encrypted_response = cp_security.encrypt_for_cp(cp_id, response)
    decrypted_response = cp_security.decrypt_from_cp(cp_id, encrypted_response)
    print(f"    ✓ Response decrypted: {decrypted_response}")
    
    # Step 6: Security monitoring
    print(f"\n[6] Security Monitoring")
    status = security_db.get_cp_security_status(cp_id)
    key_info = security_db.get_key_info(cp_id)
    print(f"    ✓ Security Status: {status['registration_status']}")
    print(f"    ✓ Last Auth: {status['last_authenticated_at']}")
    print(f"    ✓ Key Version: {key_info['key_version']}")
    print(f"    ✓ Auth Failures: {status['auth_failure_count']}")
    
    print(f"\n✓ Complete security flow executed successfully!")
    
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


async def main():
    """Run all examples."""
    print("\n" + "="*70)
    print(" EV_Central Security Extensions - Usage Examples")
    print("="*70)
    
    try:
        await example_1_authentication()
        await example_2_key_management()
        await example_3_encryption()
        await example_4_status_management()
        await example_5_integrated_flow()
        
        print("\n" + "="*70)
        print(" All examples completed successfully!")
        print("="*70)
        print("\nFor more information, see:")
        print("  - EV_CENTRAL_SECURITY_IMPLEMENTATION.md")
        print("  - evcharging/common/cp_security.py")
        print("  - evcharging/apps/ev_central/security_api.py")
        print()
    
    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
