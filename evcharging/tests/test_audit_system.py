"""
Comprehensive tests for the centralized audit logging system.

Tests cover:
- Audit event insertion
- Authentication success/failure logging
- Status change logging
- Key operation logging
- Validation error logging
- System error logging
- Security incident detection
- Brute force detection
"""

import pytest
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from evcharging.common.audit_service import AuditService, RequestContext, get_audit_service
from evcharging.common.database import AuditDB
from evcharging.common.utils import utc_now


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    yield db_path
    
    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def audit_db(temp_db):
    """Create AuditDB instance with temp database."""
    return AuditDB(temp_db)


@pytest.fixture
def audit_service(temp_db):
    """Create AuditService instance with temp database."""
    return AuditService(temp_db)


@pytest.fixture
def sample_ctx():
    """Create sample request context."""
    return RequestContext(
        request_id="test-request-123",
        ip="192.168.1.100",
        endpoint="/auth/credentials",
        http_method="POST"
    )


class TestAuditDB:
    """Test AuditDB database operations."""
    
    def test_schema_creation(self, audit_db):
        """Test that audit_events table and indexes are created."""
        # Query should work without errors
        events = audit_db.query_events()
        assert events == []
    
    def test_insert_event(self, audit_db, sample_ctx):
        """Test inserting audit event."""
        event = {
            'date_time': utc_now().isoformat(),
            'who': 'CP-001',
            'ip': sample_ctx.ip,
            'action': 'AUTH_SUCCESS',
            'description': 'Test authentication',
            'severity': 'INFO',
            'request_id': sample_ctx.request_id,
            'endpoint': sample_ctx.endpoint,
            'http_method': sample_ctx.http_method,
            'status_code': 200
        }
        
        success = audit_db.insert_event(event)
        assert success is True
        
        # Verify event was inserted
        events = audit_db.query_events()
        assert len(events) == 1
        assert events[0]['who'] == 'CP-001'
        assert events[0]['action'] == 'AUTH_SUCCESS'
    
    def test_query_events_filtering(self, audit_db, sample_ctx):
        """Test querying events with filters."""
        # Insert multiple events
        for i in range(5):
            event = {
                'date_time': utc_now().isoformat(),
                'who': f'CP-{i:03d}',
                'ip': sample_ctx.ip,
                'action': 'AUTH_SUCCESS' if i % 2 == 0 else 'AUTH_FAIL',
                'description': f'Test event {i}',
                'severity': 'INFO' if i % 2 == 0 else 'WARN',
                'request_id': f'req-{i}',
                'endpoint': sample_ctx.endpoint,
                'http_method': sample_ctx.http_method
            }
            audit_db.insert_event(event)
        
        # Query by action
        auth_success_events = audit_db.query_events(action='AUTH_SUCCESS')
        assert len(auth_success_events) == 3
        
        # Query by severity
        warn_events = audit_db.query_events(severity='WARN')
        assert len(warn_events) == 2
        
        # Query by who
        cp001_events = audit_db.query_events(who='CP-001')
        assert len(cp001_events) == 1
    
    def test_get_recent_auth_failures(self, audit_db):
        """Test retrieving recent authentication failures."""
        ctx = RequestContext(
            request_id="test-123",
            ip="10.0.0.1",
            endpoint="/auth/credentials",
            http_method="POST"
        )
        
        # Insert auth failures
        for i in range(7):
            event = {
                'date_time': utc_now().isoformat(),
                'who': 'CP-001',
                'ip': ctx.ip,
                'action': 'AUTH_FAIL',
                'description': f'Failed attempt {i}',
                'severity': 'WARN',
                'request_id': f'req-{i}',
                'endpoint': ctx.endpoint,
                'http_method': ctx.http_method
            }
            audit_db.insert_event(event)
        
        # Get recent failures by IP
        failures = audit_db.get_recent_auth_failures(ip=ctx.ip, minutes=10)
        assert len(failures) == 7
        
        # Get recent failures by CP
        cp_failures = audit_db.get_recent_auth_failures(cp_id='CP-001', minutes=10)
        assert len(cp_failures) == 7


class TestAuditService:
    """Test AuditService logging methods."""
    
    def test_auth_success(self, audit_service, sample_ctx):
        """Test logging authentication success."""
        success = audit_service.auth_success(
            cp_id='CP-001',
            ctx=sample_ctx,
            metadata={'security_status': 'ACTIVE'}
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='AUTH_SUCCESS')
        assert len(events) == 1
        assert events[0]['who'] == 'CP-001'
        assert events[0]['severity'] == 'INFO'
        assert events[0]['status_code'] == 200
    
    def test_auth_fail(self, audit_service, sample_ctx):
        """Test logging authentication failure."""
        success = audit_service.auth_fail(
            cp_id_or_unknown='CP-002',
            ctx=sample_ctx,
            reason_code=audit_service.REASON_INVALID_CREDENTIALS,
            description='Invalid credentials provided'
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='AUTH_FAIL')
        assert len(events) == 1
        assert events[0]['who'] == 'CP-002'
        assert events[0]['severity'] == 'WARN'
        assert events[0]['reason_code'] == audit_service.REASON_INVALID_CREDENTIALS
    
    def test_status_change(self, audit_service, sample_ctx):
        """Test logging status change."""
        success = audit_service.status_change(
            cp_id='CP-001',
            ctx=sample_ctx,
            old_status='ACTIVE',
            new_status='OUT_OF_SERVICE',
            reason='Maintenance scheduled'
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='STATUS_CHANGE')
        assert len(events) == 1
        assert events[0]['who'] == 'CP-001'
        assert 'ACTIVE' in events[0]['description']
        assert 'OUT_OF_SERVICE' in events[0]['description']
    
    def test_key_operations(self, audit_service, sample_ctx):
        """Test logging key operations."""
        # Test key generation
        audit_service.key_generate(cp_id='CP-001', ctx=sample_ctx)
        gen_events = audit_service.audit_db.query_events(action='KEY_GENERATE')
        assert len(gen_events) == 1
        
        # Test key reset
        audit_service.key_reset(cp_id='CP-001', ctx=sample_ctx, reason='Security rotation')
        reset_events = audit_service.audit_db.query_events(action='KEY_RESET')
        assert len(reset_events) == 1
        assert reset_events[0]['severity'] == 'WARN'
        
        # Test key revoke
        audit_service.key_revoke(cp_id='CP-001', ctx=sample_ctx, reason='CP compromised')
        revoke_events = audit_service.audit_db.query_events(action='KEY_REVOKE')
        assert len(revoke_events) == 1
        assert revoke_events[0]['severity'] == 'WARN'
    
    def test_validation_error(self, audit_service, sample_ctx):
        """Test logging validation errors."""
        success = audit_service.validation_error(
            ctx=sample_ctx,
            fields_summary='body.cp_id:field_required, body.credentials:str_too_short',
            who='unknown',
            metadata={'error_count': 2}
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='VALIDATION_ERROR')
        assert len(events) == 1
        assert events[0]['severity'] == 'WARN'
        assert events[0]['status_code'] == 422
    
    def test_error(self, audit_service, sample_ctx):
        """Test logging system errors."""
        success = audit_service.error(
            ctx=sample_ctx,
            error_type='ValueError',
            safe_message='Invalid configuration parameter',
            who='system'
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='ERROR')
        assert len(events) == 1
        assert events[0]['severity'] == 'ERROR'
        assert events[0]['who'] == 'system'
    
    def test_incident(self, audit_service, sample_ctx):
        """Test logging security incidents."""
        success = audit_service.incident(
            who_or_unknown='CP-001',
            ctx=sample_ctx,
            incident_type=audit_service.INCIDENT_BRUTE_FORCE,
            description='Brute force attack detected',
            metadata={'failure_count': 10}
        )
        
        assert success is True
        
        # Verify event
        events = audit_service.audit_db.query_events(action='INCIDENT')
        assert len(events) == 1
        assert events[0]['severity'] == 'CRITICAL'
        assert events[0]['reason_code'] == audit_service.INCIDENT_BRUTE_FORCE
    
    def test_metadata_sanitization(self, audit_service):
        """Test that sensitive metadata is redacted."""
        event_dict = {
            'date_time': utc_now().isoformat(),
            'who': 'CP-001',
            'ip': '10.0.0.1',
            'action': 'TEST',
            'description': 'Test',
            'severity': 'INFO',
            'metadata_json': audit_service._sanitize_metadata({
                'username': 'admin',
                'token': 'secret-token-value',
                'credentials': 'secret-creds',
                'password': 'mypassword',
                'safe_field': 'visible'
            })
        }
        
        # Check that sensitive fields are redacted
        import json
        metadata = json.loads(event_dict['metadata_json'])
        assert metadata['token'] == '***REDACTED***'
        assert metadata['credentials'] == '***REDACTED***'
        assert metadata['password'] == '***REDACTED***'
        assert metadata['safe_field'] == 'visible'


class TestBruteForceDetection:
    """Test brute force attack detection."""
    
    def test_brute_force_detection_threshold(self, audit_service):
        """Test that brute force is detected after threshold."""
        ctx = RequestContext(
            request_id="test-123",
            ip="10.0.0.5",
            endpoint="/auth/credentials",
            http_method="POST"
        )
        
        # Simulate 4 failed attempts (below threshold)
        for i in range(4):
            audit_service.auth_fail(
                cp_id_or_unknown='CP-001',
                ctx=ctx,
                reason_code=audit_service.REASON_INVALID_CREDENTIALS
            )
        
        # Should not trigger incident yet
        is_suspected = audit_service.check_brute_force(ip=ctx.ip)
        assert is_suspected is False
        
        # 5th attempt should trigger
        audit_service.auth_fail(
            cp_id_or_unknown='CP-001',
            ctx=ctx,
            reason_code=audit_service.REASON_INVALID_CREDENTIALS
        )
        
        is_suspected = audit_service.check_brute_force(ip=ctx.ip)
        assert is_suspected is True
    
    def test_detect_and_report_brute_force(self, audit_service):
        """Test automatic incident reporting on brute force."""
        ctx = RequestContext(
            request_id="test-456",
            ip="10.0.0.10",
            endpoint="/auth/credentials",
            http_method="POST"
        )
        
        # Simulate threshold failures
        for i in range(5):
            audit_service.auth_fail(
                cp_id_or_unknown='CP-002',
                ctx=ctx,
                reason_code=audit_service.REASON_INVALID_CREDENTIALS
            )
        
        # Detect and report
        incident_reported = audit_service.detect_and_report_brute_force('CP-002', ctx)
        assert incident_reported is True
        
        # Verify incident was logged
        incidents = audit_service.audit_db.query_events(action='INCIDENT')
        assert len(incidents) == 1
        assert incidents[0]['reason_code'] == audit_service.INCIDENT_BRUTE_FORCE
    
    def test_brute_force_per_cp_detection(self, audit_service):
        """Test brute force detection per CP ID."""
        # Different IPs, same CP
        for i in range(6):
            ctx = RequestContext(
                request_id=f"req-{i}",
                ip=f"10.0.0.{i}",
                endpoint="/auth/credentials",
                http_method="POST"
            )
            audit_service.auth_fail(
                cp_id_or_unknown='CP-003',
                ctx=ctx,
                reason_code=audit_service.REASON_INVALID_CREDENTIALS
            )
        
        # Should detect brute force for this CP
        ctx = RequestContext(
            request_id="final",
            ip="10.0.0.99",
            endpoint="/auth/credentials",
            http_method="POST"
        )
        
        incident_reported = audit_service.detect_and_report_brute_force('CP-003', ctx)
        assert incident_reported is True


class TestRequestContext:
    """Test RequestContext model."""
    
    def test_context_creation(self):
        """Test creating request context."""
        ctx = RequestContext(
            request_id="abc-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            http_method="GET"
        )
        
        assert ctx.request_id == "abc-123"
        assert ctx.ip == "192.168.1.1"
        assert ctx.endpoint == "/api/test"
        assert ctx.http_method == "GET"
    
    def test_context_immutability(self):
        """Test that RequestContext is immutable."""
        ctx = RequestContext(
            request_id="test",
            ip="127.0.0.1",
            endpoint="/test",
            http_method="POST"
        )
        
        # Should raise error when trying to modify
        with pytest.raises(Exception):
            ctx.ip = "10.0.0.1"


class TestAuditServiceSingleton:
    """Test audit service singleton pattern."""
    
    def test_singleton_instance(self, temp_db):
        """Test that get_audit_service returns same instance."""
        # Clear global instance first
        import evcharging.common.audit_service as audit_module
        audit_module._audit_service_instance = None
        
        service1 = get_audit_service(temp_db)
        service2 = get_audit_service(temp_db)
        
        assert service1 is service2


class TestAuditIntegration:
    """Integration tests for audit system."""
    
    def test_full_auth_flow_with_audit(self, audit_service, sample_ctx):
        """Test complete authentication flow with audit logging."""
        # Simulate successful auth
        audit_service.auth_success('CP-001', sample_ctx)
        
        # Simulate failed attempts from different CP
        for i in range(3):
            ctx = RequestContext(
                request_id=f"fail-{i}",
                ip="10.0.0.50",
                endpoint="/auth/credentials",
                http_method="POST"
            )
            audit_service.auth_fail(
                'CP-002',
                ctx,
                audit_service.REASON_INVALID_CREDENTIALS
            )
        
        # Verify all events logged
        all_events = audit_service.audit_db.query_events()
        assert len(all_events) == 4
        
        success_events = audit_service.audit_db.query_events(action='AUTH_SUCCESS')
        assert len(success_events) == 1
        
        fail_events = audit_service.audit_db.query_events(action='AUTH_FAIL')
        assert len(fail_events) == 3
    
    def test_audit_with_status_changes(self, audit_service, sample_ctx):
        """Test audit logging through status changes."""
        # Initial active status
        audit_service.auth_success('CP-001', sample_ctx)
        
        # Change to out of service
        audit_service.status_change(
            'CP-001',
            sample_ctx,
            'ACTIVE',
            'OUT_OF_SERVICE',
            'Scheduled maintenance'
        )
        
        # Restore to active
        audit_service.status_change(
            'CP-001',
            sample_ctx,
            'OUT_OF_SERVICE',
            'ACTIVE',
            'Maintenance completed'
        )
        
        # Verify events
        status_changes = audit_service.audit_db.query_events(action='STATUS_CHANGE')
        assert len(status_changes) == 2
        
        # Verify chronological order
        assert 'OUT_OF_SERVICE' in status_changes[1]['description']
        assert 'ACTIVE' in status_changes[0]['description']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
