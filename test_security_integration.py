#!/usr/bin/env python3
"""
Integration test for security features without Kafka.
Tests the security components integrated into EVCentralController.
"""

import sys
import asyncio
import pytest
from pathlib import Path
from datetime import datetime

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from evcharging.common.config import CentralConfig
from evcharging.apps.ev_central.main import EVCentralController, ChargingPoint
from evcharging.common.messages import CPRegistration
from loguru import logger

# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="INFO"
)


@pytest.mark.asyncio
async def test_security_integration():
    """Test security features integrated into EVCentralController."""
    
    print("\n" + "=" * 70)
    print("EV_Central Security Integration Test")
    print("=" * 70)
    
    # Create controller with minimal config
    config = CentralConfig(
        kafka_bootstrap="localhost:9092",  # Not used in this test
        listen_port=7000,
        http_port=8000,
        db_url="test_security_integration.db"
    )
    
    controller = EVCentralController(config)
    
    # Test 1: Register a CP
    print("\n[Test 1] Register Charging Point")
    print("-" * 70)
    
    registration = CPRegistration(
        cp_id="TEST-CP-001",
        cp_e_host="localhost",
        cp_e_port=5001
    )
    
    result = controller.register_cp(registration)
    assert result, "CP registration failed"
    assert "TEST-CP-001" in controller.charging_points
    
    cp = controller.charging_points["TEST-CP-001"]
    print(f"✓ CP registered: {cp.cp_id}")
    print(f"  - State: {cp.state.value}")
    print(f"  - Security Status: {cp.security_status.value}")
    print(f"  - Has Encryption Key: {cp.has_encryption_key}")
    print(f"  - Authenticated: {cp.is_authenticated}")
    
    # Test 2: Authenticate CP with credentials
    print("\n[Test 2] Authenticate CP with Credentials")
    print("-" * 70)
    
    # First register CP in registry with credentials
    test_credentials = "test-secret-credentials-abc123"
    credentials_hash = controller.security_manager.hash_credentials(test_credentials)
    
    controller.registry_db.register_cp(
        cp_id="TEST-CP-001",
        location="Test Location",
        credentials_hash=credentials_hash
    )
    
    credentials = test_credentials
    
    print(f"  CP Credentials: {credentials[:20]}...")
    
    # Authenticate
    auth_success = controller.authenticate_cp_with_credentials("TEST-CP-001", credentials)
    assert auth_success, "Authentication should succeed"
    
    cp = controller.charging_points["TEST-CP-001"]
    print(f"✓ Authentication successful")
    print(f"  - Authenticated: {cp.is_authenticated}")
    print(f"  - Token: {cp.auth_token[:50] if cp.auth_token else 'None'}...")
    print(f"  - Last Auth: {cp.last_auth_time}")
    print(f"  - Security Authorized: {cp.is_security_authorized()}")
    
    # Test 3: Test wrong credentials
    print("\n[Test 3] Test Wrong Credentials")
    print("-" * 70)
    
    # Register another CP
    registration2 = CPRegistration(
        cp_id="TEST-CP-002",
        cp_e_host="localhost",
        cp_e_port=5002
    )
    controller.register_cp(registration2)
    
    test_credentials2 = "test-secret-credentials-xyz789"
    credentials_hash2 = controller.security_manager.hash_credentials(test_credentials2)
    
    controller.registry_db.register_cp(
        cp_id="TEST-CP-002",
        location="Test Location 2",
        credentials_hash=credentials_hash2
    )
    
    # Try wrong credentials
    auth_failed = controller.authenticate_cp_with_credentials(
        "TEST-CP-002",
        "wrong-credentials-abc123"
    )
    
    assert not auth_failed, "Authentication should fail with wrong credentials"
    cp2 = controller.charging_points["TEST-CP-002"]
    print(f"✓ Wrong credentials correctly rejected")
    print(f"  - Authenticated: {cp2.is_authenticated}")
    print(f"  - Security Authorized: {cp2.is_security_authorized()}")
    
    # Test 4: Verify token authentication
    print("\n[Test 4] Token Authentication")
    print("-" * 70)
    
    # Use token from TEST-CP-001
    token = cp.auth_token
    
    # Create new CP and try to authenticate with token
    registration3 = CPRegistration(
        cp_id="TEST-CP-003",
        cp_e_host="localhost",
        cp_e_port=5003
    )
    controller.register_cp(registration3)
    
    # This should fail - token is for TEST-CP-001, not TEST-CP-003
    token_auth = controller.authenticate_cp_with_token("TEST-CP-003", token)
    assert not token_auth, "Token for wrong CP should be rejected"
    print(f"✓ Token for wrong CP correctly rejected")
    
    # Now authenticate TEST-CP-001 with its token
    token_auth = controller.authenticate_cp_with_token("TEST-CP-001", token)
    assert token_auth, "Valid token should authenticate"
    print(f"✓ Valid token authenticated successfully")
    
    # Test 5: CP Status Management
    print("\n[Test 5] CP Status Management")
    print("-" * 70)
    
    # Set CP out of service
    controller.set_cp_out_of_service("TEST-CP-001", "Scheduled maintenance")
    cp = controller.charging_points["TEST-CP-001"]
    assert cp.security_status.value == "OUT_OF_SERVICE"
    assert not cp.is_available()
    print(f"✓ CP set to OUT_OF_SERVICE")
    print(f"  - Status: {cp.security_status.value}")
    print(f"  - Available: {cp.is_available()}")
    
    # Restore to active
    controller.restore_cp_to_active("TEST-CP-001")
    cp = controller.charging_points["TEST-CP-001"]
    assert cp.security_status.value == "ACTIVE"
    print(f"✓ CP restored to ACTIVE")
    print(f"  - Status: {cp.security_status.value}")
    
    # Test 6: Encryption
    print("\n[Test 6] End-to-End Encryption")
    print("-" * 70)
    
    # Encrypt payload for CP
    command_payload = {
        "command": "START_SUPPLY",
        "session_id": "test-session-123",
        "driver_id": "test-driver-001"
    }
    
    encrypted = controller.cp_security.encrypt_for_cp("TEST-CP-001", command_payload)
    assert encrypted, "Encryption should succeed"
    print(f"✓ Command encrypted")
    print(f"  - Length: {len(encrypted)} chars")
    print(f"  - Preview: {encrypted[:60]}...")
    
    # Decrypt response from CP
    response_payload = {
        "status": "SUPPLYING",
        "kw": 22.5,
        "kwh": 1.2
    }
    
    encrypted_response = controller.cp_security.encrypt_for_cp("TEST-CP-001", response_payload)
    decrypted = controller.cp_security.decrypt_from_cp("TEST-CP-001", encrypted_response)
    
    assert decrypted == response_payload, "Decryption should return original payload"
    print(f"✓ Response decrypted successfully")
    print(f"  - Original: {response_payload}")
    print(f"  - Decrypted: {decrypted}")
    
    # Test 7: CP Revocation
    print("\n[Test 7] CP Revocation (Critical Security)")
    print("-" * 70)
    
    controller.revoke_cp_access("TEST-CP-002", "Security incident detected")
    cp2 = controller.charging_points["TEST-CP-002"]
    
    assert cp2.security_status.value == "REVOKED"
    assert not cp2.is_authenticated
    assert not cp2.is_available()
    print(f"✓ CP access revoked")
    print(f"  - Status: {cp2.security_status.value}")
    print(f"  - Authenticated: {cp2.is_authenticated}")
    print(f"  - Available: {cp2.is_available()}")
    
    # Test 8: Dashboard Data with Security
    print("\n[Test 8] Dashboard Data")
    print("-" * 70)
    
    dashboard_data = controller.get_dashboard_data()
    
    print(f"✓ Dashboard data includes security info")
    print(f"  - Total CPs: {len(dashboard_data['charging_points'])}")
    
    for cp_data in dashboard_data["charging_points"]:
        print(f"\n  CP: {cp_data['cp_id']}")
        print(f"    - State: {cp_data['state']}")
        print(f"    - Security Status: {cp_data['security_status']}")
        print(f"    - Authenticated: {cp_data['is_authenticated']}")
        print(f"    - Has Encryption Key: {cp_data['has_encryption_key']}")
    
    # Summary
    print("\n" + "=" * 70)
    print("✓ ALL INTEGRATION TESTS PASSED")
    print("=" * 70)
    print("\nSecurity features successfully integrated into EVCentralController:")
    print("  ✓ CP registration with automatic security initialization")
    print("  ✓ Credential-based authentication")
    print("  ✓ Token-based authentication")
    print("  ✓ Wrong credential rejection")
    print("  ✓ Token validation and CP verification")
    print("  ✓ Status management (ACTIVE/OUT_OF_SERVICE/REVOKED)")
    print("  ✓ End-to-end encryption (encrypt_for_cp/decrypt_from_cp)")
    print("  ✓ CP revocation")
    print("  ✓ Security info in dashboard")
    print("\n")


if __name__ == "__main__":
    asyncio.run(test_security_integration())
