#!/usr/bin/env python3
"""
EV_Central Security Extensions - Implementation Verification

Verifies that all security components are properly installed and functional.
Run this script after deployment to ensure everything is working correctly.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def verify_imports():
    """Verify all security components can be imported."""
    print("=" * 60)
    print("1. Verifying Imports")
    print("=" * 60)
    
    try:
        from evcharging.common.cp_security import (
            CPSecurityService,
            CPEncryptionService,
            CPSecurityStatus,
            CPAuthResult
        )
        print("✓ evcharging.common.cp_security imports OK")
        
        from evcharging.common.database import CPSecurityDB
        print("✓ CPSecurityDB imports OK")
        
        from evcharging.apps.ev_central.security_api import create_security_api
        print("✓ Security API imports OK")
        
        from evcharging.apps.ev_central.main import EVCentralController
        print("✓ EVCentralController imports OK")
        
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False


def verify_database_schema():
    """Verify database schema is correct."""
    print("\n" + "=" * 60)
    print("2. Verifying Database Schema")
    print("=" * 60)
    
    try:
        from evcharging.common.database import FaultHistoryDB
        import sqlite3
        import tempfile
        
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        # Initialize database (creates tables)
        db = FaultHistoryDB(db_path)
        
        # Verify tables exist
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check cp_encryption_keys table
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='cp_encryption_keys'
        """)
        if cursor.fetchone():
            print("✓ cp_encryption_keys table exists")
        else:
            print("✗ cp_encryption_keys table missing")
            return False
        
        # Check cp_security_status table
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='cp_security_status'
        """)
        if cursor.fetchone():
            print("✓ cp_security_status table exists")
        else:
            print("✗ cp_security_status table missing")
            return False
        
        # Check cp_registry table
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='cp_registry'
        """)
        if cursor.fetchone():
            print("✓ cp_registry table exists")
        else:
            print("✗ cp_registry table missing")
            return False
        
        conn.close()
        
        # Cleanup
        Path(db_path).unlink()
        
        return True
    except Exception as e:
        print(f"✗ Database verification error: {e}")
        return False


def verify_encryption():
    """Verify encryption works correctly."""
    print("\n" + "=" * 60)
    print("3. Verifying Encryption")
    print("=" * 60)
    
    try:
        from evcharging.common.cp_security import CPEncryptionService
        import json
        
        # Generate key
        key = CPEncryptionService.generate_key()
        print(f"✓ Generated 256-bit key ({len(key)} bytes)")
        
        # Test encryption/decryption
        test_payload = {"test": "data", "number": 123}
        payload_json = json.dumps(test_payload)
        
        encrypted = CPEncryptionService.encrypt_payload(payload_json, key)
        print(f"✓ Encryption successful ({len(encrypted)} chars)")
        
        decrypted_json = CPEncryptionService.decrypt_payload(encrypted, key)
        decrypted = json.loads(decrypted_json)
        
        if decrypted == test_payload:
            print("✓ Decryption successful - payloads match")
        else:
            print("✗ Decryption failed - payloads don't match")
            return False
        
        # Test with wrong key
        wrong_key = CPEncryptionService.generate_key()
        try:
            CPEncryptionService.decrypt_payload(encrypted, wrong_key)
            print("✗ ERROR: Wrong key should have failed!")
            return False
        except ValueError:
            print("✓ Correctly rejected wrong key")
        
        return True
    except Exception as e:
        print(f"✗ Encryption verification error: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_authentication():
    """Verify authentication works correctly."""
    print("\n" + "=" * 60)
    print("4. Verifying Authentication")
    print("=" * 60)
    
    try:
        from evcharging.common.cp_security import CPSecurityService
        from evcharging.common.database import CPSecurityDB, CPRegistryDB
        from evcharging.common.security import create_security_manager
        import tempfile
        
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        # Initialize components
        security_db = CPSecurityDB(db_path)
        registry_db = CPRegistryDB(db_path)
        security_manager = create_security_manager(
            secret_key="test-secret-key-minimum-32-characters!!!"
        )
        
        cp_security = CPSecurityService(
            security_db=security_db,
            registry_db=registry_db,
            security_manager=security_manager,
            db_path=db_path
        )
        
        # Register a test CP
        cp_id = "TEST-CP-VERIFY"
        credentials = "test-credentials-secret"
        credentials_hash = security_manager.hash_credentials(credentials)
        
        registry_db.register_cp(
            cp_id=cp_id,
            location="Test Location",
            credentials_hash=credentials_hash
        )
        print("✓ Test CP registered")
        
        # Initialize security
        security_db.initialize_cp_security(cp_id)
        cp_security.generate_key_for_cp(cp_id)
        print("✓ Security initialized")
        
        # Test authentication with correct credentials
        auth_result = cp_security.authenticate_cp(cp_id, credentials)
        if auth_result.success and auth_result.is_authorized():
            print("✓ Authentication successful")
            print(f"✓ Token issued: {auth_result.token[:40]}...")
        else:
            print(f"✗ Authentication failed: {auth_result.reason}")
            return False
        
        # Test authentication with wrong credentials
        auth_result = cp_security.authenticate_cp(cp_id, "wrong-credentials")
        if not auth_result.success:
            print("✓ Correctly rejected invalid credentials")
        else:
            print("✗ ERROR: Should have rejected invalid credentials!")
            return False
        
        # Cleanup
        Path(db_path).unlink()
        
        return True
    except Exception as e:
        print(f"✗ Authentication verification error: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_status_management():
    """Verify status management works correctly."""
    print("\n" + "=" * 60)
    print("5. Verifying Status Management")
    print("=" * 60)
    
    try:
        from evcharging.common.cp_security import CPSecurityService, CPSecurityStatus
        from evcharging.common.database import CPSecurityDB, CPRegistryDB
        from evcharging.common.security import create_security_manager
        import tempfile
        
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        # Initialize components
        security_db = CPSecurityDB(db_path)
        registry_db = CPRegistryDB(db_path)
        security_manager = create_security_manager(
            secret_key="test-secret-key-minimum-32-characters!!!"
        )
        
        cp_security = CPSecurityService(
            security_db=security_db,
            registry_db=registry_db,
            security_manager=security_manager,
            db_path=db_path
        )
        
        cp_id = "TEST-STATUS-CP"
        
        # Initialize as ACTIVE
        security_db.initialize_cp_security(cp_id)
        status = cp_security.get_security_status(cp_id)
        if status == CPSecurityStatus.ACTIVE:
            print("✓ Initialized as ACTIVE")
        else:
            print(f"✗ Expected ACTIVE, got {status.value}")
            return False
        
        # Set OUT_OF_SERVICE
        cp_security.set_out_of_service(cp_id, reason="Test")
        status = cp_security.get_security_status(cp_id)
        if status == CPSecurityStatus.OUT_OF_SERVICE:
            print("✓ Set to OUT_OF_SERVICE")
        else:
            print(f"✗ Expected OUT_OF_SERVICE, got {status.value}")
            return False
        
        # Restore to ACTIVE
        cp_security.restore_to_active(cp_id)
        status = cp_security.get_security_status(cp_id)
        if status == CPSecurityStatus.ACTIVE:
            print("✓ Restored to ACTIVE")
        else:
            print(f"✗ Expected ACTIVE, got {status.value}")
            return False
        
        # REVOKE
        cp_security.revoke_cp(cp_id, reason="Test")
        status = cp_security.get_security_status(cp_id)
        if status == CPSecurityStatus.REVOKED:
            print("✓ Revoked successfully")
        else:
            print(f"✗ Expected REVOKED, got {status.value}")
            return False
        
        # Cleanup
        Path(db_path).unlink()
        
        return True
    except Exception as e:
        print(f"✗ Status management verification error: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_documentation():
    """Verify documentation files exist."""
    print("\n" + "=" * 60)
    print("6. Verifying Documentation")
    print("=" * 60)
    
    # Get the project root directory
    project_root = Path(__file__).parent
    
    docs = [
        "EV_CENTRAL_SECURITY_README.md",
        "EV_CENTRAL_SECURITY_IMPLEMENTATION.md",
        "EV_CENTRAL_SECURITY_SUMMARY.md",
        "EV_CENTRAL_SECURITY_QUICKREF.md",
        "EV_CENTRAL_SECURITY_DEPLOYMENT.md"
    ]
    
    all_exist = True
    for doc in docs:
        path = project_root / doc
        if path.exists():
            size_kb = path.stat().st_size / 1024
            print(f"✓ {doc} ({size_kb:.1f} KB)")
        else:
            print(f"✗ {doc} MISSING")
            all_exist = False
    
    # Check examples
    examples_path = project_root / "examples" / "security_examples.py"
    if examples_path.exists():
        print(f"✓ examples/security_examples.py")
    else:
        print(f"✗ examples/security_examples.py MISSING")
        all_exist = False
    
    return all_exist


def main():
    """Run all verifications."""
    print("\n" + "=" * 60)
    print("EV_Central Security Extensions - Verification")
    print("=" * 60)
    
    results = {
        "Imports": verify_imports(),
        "Database Schema": verify_database_schema(),
        "Encryption": verify_encryption(),
        "Authentication": verify_authentication(),
        "Status Management": verify_status_management(),
        "Documentation": verify_documentation()
    }
    
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    all_passed = True
    for test, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL VERIFICATIONS PASSED")
        print("=" * 60)
        print("\nThe security implementation is correctly installed and functional.")
        print("\nNext steps:")
        print("  1. Run examples: python examples/security_examples.py")
        print("  2. Review documentation: EV_CENTRAL_SECURITY_README.md")
        print("  3. Start EV_Central with security enabled")
        print()
        return 0
    else:
        print("✗ SOME VERIFICATIONS FAILED")
        print("=" * 60)
        print("\nPlease review the errors above and fix the issues.")
        print("Contact the development team if you need assistance.")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
