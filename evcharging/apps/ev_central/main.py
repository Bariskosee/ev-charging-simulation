"""
EV Central - Main controller service.

Responsibilities:
- Accept and route driver charging requests
- Manage charging point availability
- Coordinate commands to CP_E
- Provide dashboard for monitoring
"""

import asyncio
import argparse
import sys
import os
import json
from enum import Enum
from typing import Dict, Optional
from datetime import datetime, timedelta
from loguru import logger

from evcharging.common.config import CentralConfig, TOPICS
from evcharging.common.kafka import KafkaProducerHelper, KafkaConsumerHelper, ensure_topics
from evcharging.common.messages import (
    DriverRequest, DriverUpdate, MessageStatus, CentralCommand, CommandType,
    CPStatus, CPTelemetry, CPSessionTicket, CPRegistration
)
from evcharging.common.charging_points import get_metadata
from evcharging.common.states import CPState, can_supply
from evcharging.common.utils import utc_now, generate_id
from evcharging.common.circuit_breaker import CircuitBreaker, CircuitState
from evcharging.common.database import FaultHistoryDB, CPSecurityDB, CPRegistryDB
from evcharging.common.security import create_security_manager
from evcharging.common.cp_security import CPSecurityService, CPSecurityStatus
from evcharging.common.registry_client import RegistryClient
from evcharging.common.encrypted_kafka import (
    EncryptedKafkaHandler, 
    create_encrypted_kafka_handler,
    get_encryption_error_tracker,
    EncryptionErrorType
)

from evcharging.apps.ev_central.dashboard import create_dashboard_app
from evcharging.apps.ev_central.tcp_server import TCPControlServer
from evcharging.common.error_manager import (
    ErrorManager, ErrorCategory, ErrorSeverity, ErrorSource,
    get_error_manager, report_connection_error, report_cp_unavailable,
    report_communication_error, report_service_error, resolve_target_errors
)


class ChargingPoint:
    """Internal representation of a charging point."""
    
    class MonitorStatus(str, Enum):
        OK = "OK"
        DOWN = "DOWN"

    def __init__(self, cp_id: str, cp_e_host: str = "", cp_e_port: int = 0):
        self.cp_id = cp_id
        self.state = CPState.DISCONNECTED
        self.current_driver: str | None = None
        self.current_session: str | None = None
        self.last_telemetry: CPTelemetry | None = None
        self.last_update: datetime = utc_now()
        self.last_seen: datetime = utc_now()
        self.cp_e_host = cp_e_host
        self.cp_e_port = cp_e_port
        self.is_faulty = False  # Track fault state from monitor
        self.fault_reason: str | None = None
        self.fault_timestamp: datetime | None = None
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=30,
            half_open_max_calls=2
        )
        # Get city from metadata if available, otherwise set to Unknown
        metadata = get_metadata(cp_id)
        self.city: str = metadata.city if metadata else "Unknown"
        self.monitor_status: ChargingPoint.MonitorStatus = ChargingPoint.MonitorStatus.DOWN
        self.monitor_last_seen: datetime | None = None
        self.engine_status_known: bool = False
        
        # Security attributes
        self.is_authenticated: bool = False
        self.auth_token: str | None = None
        self.security_status: CPSecurityStatus = CPSecurityStatus.ACTIVE
        self.last_auth_time: datetime | None = None
        self.has_encryption_key: bool = False
        
        # Encryption error tracking for display on interfaces
        self.encryption_error: str | None = None
        self.encryption_error_type: str | None = None
        self.encryption_error_timestamp: datetime | None = None
        self.communication_status: str = "OK"  # OK, ENCRYPTION_ERROR, KEY_MISMATCH
    
    def set_encryption_error(self, error_type: str, message: str):
        """Record an encryption error for display."""
        self.encryption_error = message
        self.encryption_error_type = error_type
        self.encryption_error_timestamp = utc_now()
        self.communication_status = "ENCRYPTION_ERROR"
        logger.error(f"CP {self.cp_id} encryption error: {error_type} - {message}")
    
    def clear_encryption_error(self):
        """Clear encryption error (recovery)."""
        if self.encryption_error:
            logger.info(f"CP {self.cp_id} encryption recovered - communication restored")
        self.encryption_error = None
        self.encryption_error_type = None
        self.encryption_error_timestamp = None
        self.communication_status = "OK"
    
    def is_available(self) -> bool:
        """Check if CP is available for new charging session."""
        # Check circuit breaker state
        if self.circuit_breaker.get_state() == CircuitState.OPEN:
            return False
        
        # Check security status
        if self.security_status != CPSecurityStatus.ACTIVE:
            return False
        
        return can_supply(self.state) and self.current_driver is None and not self.is_faulty
    
    def is_security_authorized(self) -> bool:
        """Check if CP is authorized from security perspective."""
        return (
            self.is_authenticated and 
            self.security_status == CPSecurityStatus.ACTIVE and
            self.has_encryption_key
        )

    def record_monitor_heartbeat(self):
        """Record heartbeat received from monitor.
        
        Also restores CP to ACTIVATED state if it was marked DISCONNECTED
        due to heartbeat timeout.
        """
        self.monitor_last_seen = utc_now()
        self.monitor_status = ChargingPoint.MonitorStatus.OK
        
        # Restore to ACTIVATED if was marked DISCONNECTED due to timeout
        if self.state == CPState.DISCONNECTED and not self.is_faulty:
            self.state = CPState.ACTIVATED
            self.engine_status_known = False  # We don't know actual engine state yet
            self.last_update = utc_now()
            logger.info(f"CP {self.cp_id}: Monitor heartbeat received - restored to ACTIVATED")

    def mark_monitor_down(self):
        """Flag the monitor as disconnected."""
        if self.monitor_status != ChargingPoint.MonitorStatus.DOWN:
            logger.warning(f"Monitor for {self.cp_id} marked DOWN (no heartbeat)")
        self.monitor_status = ChargingPoint.MonitorStatus.DOWN

    def get_display_state(self) -> str:
        """Calculate display state combining monitor and engine state."""
        if self.monitor_status == ChargingPoint.MonitorStatus.DOWN:
            return "DISCONNECTED"
        if self.is_faulty:
            return "BROKEN"
        if self.engine_status_known and self.state in {CPState.FAULT, CPState.DISCONNECTED}:
            return "BROKEN"
        if self.communication_status == "ENCRYPTION_ERROR":
            return "ENCRYPTION_ERROR"
        if self.security_status == CPSecurityStatus.REVOKED:
            return "REVOKED"
        if self.security_status == CPSecurityStatus.OUT_OF_SERVICE:
            return "OUT_OF_SERVICE"
        return "ON"


class EVCentralController:
    """Main controller managing all charging points and driver requests."""
    
    def __init__(self, config: CentralConfig):
        self.config = config
        self.producer: KafkaProducerHelper | None = None
        self.consumer: KafkaConsumerHelper | None = None
        self.charging_points: Dict[str, ChargingPoint] = {}
        self.active_requests: Dict[str, DriverRequest] = {}
        self._running = False
        self.db = FaultHistoryDB()  # Initialize database
        self.monitor_timeout = timedelta(seconds=5)
        self.weather_by_city: dict[str, dict] = {}
        
        # Security components
        self.security_db = CPSecurityDB(config.db_url or "ev_charging.db")
        self.registry_db = CPRegistryDB(config.db_url or "ev_charging.db")
        
        # Initialize security manager with secret key from environment
        # MUST match REGISTRY_SECRET_KEY for token validation to work
        secret_key = os.environ.get("EV_SECURITY_SECRET")
        if not secret_key:
            raise ValueError(
                "EV_SECURITY_SECRET environment variable is required. "
                "This MUST match REGISTRY_SECRET_KEY for JWT token validation to work."
            )
        
        self.security_manager = create_security_manager(
            secret_key=secret_key,
            token_expiration_hours=24,
            jwt_issuer="ev-registry",
            jwt_audience="ev-central"
        )
        
        # Initialize CP security service
        self.cp_security = CPSecurityService(
            security_db=self.security_db,
            registry_db=self.registry_db,
            security_manager=self.security_manager,
            db_path=config.db_url or "ev_charging.db"
        )
        
        # Initialize encrypted Kafka handler for secure CP communication
        # Enable encryption based on environment (disabled in lab mode for compatibility)
        encryption_enabled = os.environ.get("EV_KAFKA_ENCRYPTION", "false").lower() == "true"
        self.encrypted_kafka = create_encrypted_kafka_handler(
            security_service=self.cp_security,
            encryption_enabled=encryption_enabled
        )
        self.encryption_error_tracker = get_encryption_error_tracker()
        
        # System events for restoration/recovery tracking (displayed on dashboard)
        self.system_events: list[dict] = []
        self._max_system_events = 50  # Keep last 50 events
        
        # Initialize error manager for centralized error tracking
        self.error_manager = get_error_manager()
        
        # Initialize registry client for loading registered CPs
        registry_url = os.environ.get("REGISTRY_SERVICE_URL", "http://ev-registry:8080")
        self.registry_client = RegistryClient(
            registry_url=registry_url,
            verify_ssl=False  # Disable SSL verification for lab environment
        )
        
        logger.info(
            f"EV Central Controller initialized with security extensions "
            f"(Kafka encryption: {'enabled' if encryption_enabled else 'disabled'})"
        )
    
    def _add_system_event(self, event_type: str, component: str, message: str, severity: str = "INFO"):
        """Add a system event for display on dashboard.
        
        Args:
            event_type: Type of event (RESTORATION, FAILURE, WARNING, etc.)
            component: Component name (CP-001, Kafka, Central, etc.)
            message: Human-readable message
            severity: INFO, WARNING, ERROR, SUCCESS
        """
        event = {
            "timestamp": utc_now().isoformat(),
            "type": event_type,
            "component": component,
            "message": message,
            "severity": severity
        }
        self.system_events.insert(0, event)  # Add to beginning (newest first)
        
        # Trim to max size
        if len(self.system_events) > self._max_system_events:
            self.system_events = self.system_events[:self._max_system_events]
        
        # Log based on severity
        if severity == "ERROR":
            logger.error(f"[{event_type}] {component}: {message}")
        elif severity == "WARNING":
            logger.warning(f"[{event_type}] {component}: {message}")
        elif severity == "SUCCESS":
            logger.info(f"✅ [{event_type}] {component}: {message}")
        else:
            logger.info(f"[{event_type}] {component}: {message}")
    
    async def _load_cps_from_registry(self):
        """Load all registered charging points from EV Registry."""
        try:
            logger.info("Loading registered charging points from EV Registry...")
            cps = await self.registry_client.list_registered_cps(status_filter="REGISTERED")
            
            if not cps:
                logger.info("No registered CPs found in registry")
                return
            
            loaded_count = 0
            for cp_info in cps:
                cp_id = cp_info.get("cp_id")
                if not cp_id:
                    continue
                
                # Create ChargingPoint instance if not already exists
                if cp_id not in self.charging_points:
                    self.charging_points[cp_id] = ChargingPoint(cp_id)
                    logger.info(f"Loaded CP {cp_id} from registry (Location: {cp_info.get('location', 'Unknown')})")
                    loaded_count += 1
                
                # Set initial state
                cp = self.charging_points[cp_id]
                cp.state = CPState.DISCONNECTED  # Will update when monitor connects
                cp.last_update = utc_now()
                
                # Try to get city from metadata
                metadata = get_metadata(cp_id)
                if metadata:
                    cp.city = metadata.city
                    self.weather_by_city.update({metadata.city: None})
                else:
                    # Use location from registry if metadata not available
                    location = cp_info.get('location', 'Unknown')
                    cp.city = location
                    logger.debug(f"No metadata for {cp_id}, using registry location: {location}")
                
                # Mark as registered (authenticated status will be updated when CP connects)
                cp.is_authenticated = False
                cp.security_status = CPSecurityStatus.PENDING
            
            logger.info(f"Loaded {loaded_count} charging points from EV Registry")
            
            if loaded_count > 0:
                self._add_system_event(
                    "INITIALIZATION",
                    "Registry",
                    f"Loaded {loaded_count} registered charging points from EV Registry",
                    "SUCCESS"
                )
        
        except Exception as e:
            logger.warning(f"Failed to load CPs from registry: {e}")
            self._add_system_event(
                "INITIALIZATION",
                "Registry",
                f"Failed to load CPs from registry: {e}",
                "WARNING"
            )
    
    async def start(self):
        """Initialize and start the central controller."""
        logger.info("Starting EV Central Controller...")
        
        # Load registered CPs from Registry
        await self._load_cps_from_registry()
        
        # Ensure Kafka topics exist
        await ensure_topics(
            self.config.kafka_bootstrap,
            list(TOPICS.values())
        )
        
        # Initialize Kafka producer
        self.producer = KafkaProducerHelper(self.config.kafka_bootstrap)
        await self.producer.start()
        
        # Initialize Kafka consumer for driver requests and CP status
        self.consumer = KafkaConsumerHelper(
            self.config.kafka_bootstrap,
            topics=[TOPICS["DRIVER_REQUESTS"], TOPICS["CP_STATUS"], 
                    TOPICS["CP_TELEMETRY"], TOPICS["CP_SESSION_END"]],
            group_id="central-controller",
            auto_offset_reset="earliest"
        )
        await self.consumer.start()
        
        self._running = True
        logger.info("EV Central Controller started successfully")
    
    async def stop(self):
        """Stop the controller gracefully."""
        logger.info("Stopping EV Central Controller...")
        self._running = False
        
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        
        logger.info("EV Central Controller stopped")
    
    def register_cp(self, registration: CPRegistration) -> bool:
        """Register a charging point from CP Monitor."""
        cp_id = registration.cp_id
        
        if cp_id not in self.charging_points:
            self.charging_points[cp_id] = ChargingPoint(
                cp_id,
                registration.cp_e_host,
                registration.cp_e_port
            )
            logger.info(f"Registered new CP: {cp_id}")
        else:
            cp = self.charging_points[cp_id]
            cp.cp_e_host = registration.cp_e_host
            cp.cp_e_port = registration.cp_e_port
            logger.info(f"Updated CP registration: {cp_id}")
        
        # Set to ACTIVATED state
        cp = self.charging_points[cp_id]
        cp.state = CPState.ACTIVATED
        cp.last_update = utc_now()
        cp.record_monitor_heartbeat()
        
        self.weather_by_city.update({get_metadata(cp_id).city: None})
        
        # Auto-authorize CP for lab environment (no EV_Registry dependency)
        cp.is_authenticated = True
        cp.has_encryption_key = True
        cp.security_status = CPSecurityStatus.ACTIVE
        logger.info(f"CP {cp_id} auto-authorized for lab environment")
        
        # Try to initialize advanced security (optional, don't fail if unavailable)
        try:
            self._initialize_cp_security(cp_id)
        except Exception as e:
            logger.debug(f"Advanced security init skipped for {cp_id}: {e}")
        
        return True
    
    def _initialize_cp_security(self, cp_id: str):
        """
        Initialize security for a CP.
        Ensures encryption key and security status exist.
        
        Args:
            cp_id: Charging point identifier
        """
        try:
            # Initialize security status
            self.security_db.initialize_cp_security(cp_id)
            
            # Generate encryption key if not exists
            key_info = self.security_db.get_key_info(cp_id)
            if not key_info:
                self.cp_security.generate_key_for_cp(cp_id)
                logger.info(f"Generated encryption key for CP {cp_id}")
            
            # Update CP security attributes
            if cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                security_status = self.cp_security.get_security_status(cp_id)
                if security_status:
                    cp.security_status = security_status
                cp.has_encryption_key = True
        
        except Exception as e:
            logger.error(f"Failed to initialize security for CP {cp_id}: {e}")
    
    def authenticate_cp_with_credentials(self, cp_id: str, credentials: str) -> bool:
        """
        Authenticate a CP using EV_Registry credentials.
        
        Args:
            cp_id: Charging point identifier
            credentials: Secret credentials from registration
            
        Returns:
            True if authenticated and authorized
        """
        try:
            auth_result = self.cp_security.authenticate_cp(cp_id, credentials)
            
            if not auth_result.success:
                logger.warning(f"Authentication failed for CP {cp_id}: {auth_result.reason}")
                return False
            
            # Update CP security state
            if cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                cp.is_authenticated = True
                cp.auth_token = auth_result.token
                cp.security_status = auth_result.status
                cp.last_auth_time = utc_now()
                
                logger.info(
                    f"CP {cp_id} authenticated successfully "
                    f"(status: {auth_result.status.value})"
                )
            
            return auth_result.is_authorized()
        
        except Exception as e:
            logger.error(f"Authentication error for CP {cp_id}: {e}")
            return False
    
    def authenticate_cp_with_token(self, cp_id: str, token: str) -> bool:
        """
        Authenticate a CP using a JWT token.
        
        Args:
            cp_id: Charging point identifier
            token: JWT access token
            
        Returns:
            True if authenticated and authorized
        """
        try:
            auth_result = self.cp_security.verify_token(token)
            
            if not auth_result or auth_result.cp_id != cp_id:
                logger.warning(f"Token verification failed for CP {cp_id}")
                return False
            
            # Update CP security state
            if cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                cp.is_authenticated = True
                cp.auth_token = token
                cp.security_status = auth_result.status
                cp.last_auth_time = utc_now()
            
            return auth_result.is_authorized()
        
        except Exception as e:
            logger.error(f"Token authentication error for CP {cp_id}: {e}")
            return False
    
    def revoke_cp_access(self, cp_id: str, reason: str = "Manual revocation"):
        """
        Revoke a CP's access (CRITICAL SECURITY OPERATION).
        
        Args:
            cp_id: Charging point identifier
            reason: Reason for revocation
        """
        try:
            # Revoke via security service
            success = self.cp_security.revoke_cp(cp_id, reason)
            
            if success and cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                cp.security_status = CPSecurityStatus.REVOKED
                cp.is_authenticated = False
                cp.auth_token = None
                
                # If CP has active session, stop it
                if cp.current_session:
                    asyncio.create_task(
                        self.send_stop_supply_command(cp_id, f"CP revoked: {reason}")
                    )
                
                logger.warning(f"CP {cp_id} access REVOKED: {reason}")
        
        except Exception as e:
            logger.error(f"Failed to revoke CP {cp_id}: {e}")
    
    def set_cp_out_of_service(self, cp_id: str, reason: str = "Maintenance"):
        """
        Mark a CP as out of service.
        
        Args:
            cp_id: Charging point identifier
            reason: Out-of-service reason
        """
        try:
            success = self.cp_security.set_out_of_service(cp_id, reason)
            
            if success and cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                cp.security_status = CPSecurityStatus.OUT_OF_SERVICE
                
                logger.info(f"CP {cp_id} set to OUT_OF_SERVICE: {reason}")
        
        except Exception as e:
            logger.error(f"Failed to set CP {cp_id} out of service: {e}")
    
    def restore_cp_to_active(self, cp_id: str):
        """
        Restore a CP from OUT_OF_SERVICE to ACTIVE.
        
        Args:
            cp_id: Charging point identifier
        """
        try:
            success = self.cp_security.restore_to_active(cp_id)
            
            if success and cp_id in self.charging_points:
                cp = self.charging_points[cp_id]
                cp.security_status = CPSecurityStatus.ACTIVE
                
                logger.info(f"CP {cp_id} restored to ACTIVE")
        
        except Exception as e:
            logger.error(f"Failed to restore CP {cp_id}: {e}")
    
    async def mark_cp_faulty(self, cp_id: str, reason: str):
        """Mark a charging point as faulty and trigger the engine reaction."""
        if cp_id not in self.charging_points:
            logger.error(f"Cannot mark unknown CP {cp_id} as faulty")
            return
        
        cp = self.charging_points[cp_id]
        cp.is_faulty = True
        cp.fault_reason = reason
        cp.fault_timestamp = utc_now()
        cp.circuit_breaker.call_failed()  # Record failure in circuit breaker
        cp.record_monitor_heartbeat()
        
        # Update engine state to reflect fault condition
        cp.state = CPState.FAULT
        cp.engine_status_known = False  # Engine status unknown until it recovers
        cp.last_update = utc_now()
        
        # Record fault event in database
        self.db.record_fault_event(cp_id, "FAULT", reason)
        
        # Add system event for dashboard display
        self._add_system_event(
            "FAILURE",
            cp_id,
            f"CP {cp_id} marked as FAULTY: {reason}",
            "ERROR"
        )
        
        # Report error to error manager for centralized tracking
        report_cp_unavailable(
            source=ErrorSource.CENTRAL,
            cp_id=cp_id,
            reason=f"CP out of service. {reason}"
        )
        
        logger.warning(
            f"CP {cp_id} marked as FAULTY: {reason} - Engine state set to FAULT "
            f"(Circuit: {cp.circuit_breaker.get_state().value})"
        )
        
        # Send STOP_CP command to the engine via Kafka to enter safe state
        if self.producer:
            try:
                command = CentralCommand(
                    cmd=CommandType.STOP_CP,
                    cp_id=cp_id,
                    payload={"reason": reason}
                )
                await self._send_encrypted_command(cp_id, command)
                logger.info(f"Sent STOP_CP command to {cp_id} due to fault: {reason}")
            except Exception as e:
                logger.error(f"Failed to send STOP_CP command to {cp_id}: {e}")
                # Report command sending failure
                report_communication_error(
                    source=ErrorSource.CENTRAL,
                    target=cp_id,
                    component=f"CP {cp_id}",
                    detail=f"Failed to send STOP_CP command: {e}"
                )
        else:
            logger.warning(f"CP {cp_id} marked as faulty but no Kafka producer available")

        # If CP has an active session, notify the driver
        if cp.current_driver:
            logger.warning(f"CP {cp_id} has active session with {cp.current_driver}, notifying driver")
            # Driver will be notified through normal status updates
    
    async def clear_cp_fault(self, cp_id: str):
        """Clear fault status from a charging point."""
        if cp_id in self.charging_points:
            cp = self.charging_points[cp_id]
            cp.is_faulty = False
            cp.fault_reason = None
            cp.fault_timestamp = None
            cp.circuit_breaker.call_succeeded()  # Record success in circuit breaker
            cp.record_monitor_heartbeat()
            
            # Reset engine state to ACTIVATED and clear engine status
            cp.state = CPState.ACTIVATED
            cp.engine_status_known = False  # Engine will send new status
            cp.last_update = utc_now()
            
            # Record recovery event in database
            self.db.record_fault_event(cp_id, "RECOVERY", "Health check restored")
            
            # Add system event for dashboard display
            self._add_system_event(
                "RESTORATION",
                cp_id,
                f"CP {cp_id} fault cleared and restored to ACTIVATED state",
                "SUCCESS"
            )
            
            # Resolve errors for this CP in error manager
            resolve_target_errors(cp_id, f"CP {cp_id} recovered - health check restored")
            
            logger.info(
                f"CP {cp_id} fault cleared, state set to ACTIVATED "
                f"(Circuit: {cp.circuit_breaker.get_state().value})"
            )
        else:
            logger.error(f"Cannot clear fault for unknown CP {cp_id}")

    def record_monitor_ping(self, cp_id: str):
        """Record heartbeat from CP Monitor."""
        if cp_id in self.charging_points:
            cp = self.charging_points[cp_id]
            
            # Track if this is a restoration (was DOWN, now OK)
            was_down = cp.monitor_status == ChargingPoint.MonitorStatus.DOWN
            was_disconnected = cp.state == CPState.DISCONNECTED
            was_pending = cp.security_status == CPSecurityStatus.PENDING
            
            cp.record_monitor_heartbeat()
            
            # Auto-authorize CP for lab environment if it was pending
            # This handles CPs loaded from registry that receive their first heartbeat
            if was_pending or not cp.is_authenticated:
                cp.is_authenticated = True
                cp.has_encryption_key = True
                cp.security_status = CPSecurityStatus.ACTIVE
                logger.info(f"CP {cp_id} auto-authorized via monitor heartbeat - security: ACTIVE")
            
            # Log restoration event if recovering from DOWN state
            if was_down or was_disconnected:
                self._add_system_event(
                    "RESTORATION",
                    cp_id,
                    f"CP {cp_id} monitor connection restored - service resumed",
                    "SUCCESS"
                )
        else:
            logger.warning(f"Heartbeat from unregistered CP monitor: {cp_id} - creating and activating placeholder entry")
            # Create placeholder and immediately activate it since monitor is alive
            cp = ChargingPoint(cp_id)
            cp.state = CPState.ACTIVATED  # Set to ACTIVATED instead of DISCONNECTED
            
            # Auto-authorize CP for lab environment
            cp.is_authenticated = True
            cp.has_encryption_key = True
            cp.security_status = CPSecurityStatus.ACTIVE
            
            cp.record_monitor_heartbeat()
            self.charging_points[cp_id] = cp
            
            # Log the auto-registration
            logger.info(f"CP {cp_id} auto-registered via monitor heartbeat - state: ACTIVATED, security: ACTIVE")

    async def handle_driver_request(self, request: DriverRequest):
        """Process a driver charging request."""
        logger.info(
            f"Driver request received: driver={request.driver_id}, "
            f"cp={request.cp_id}, request_id={request.request_id}"
        )
        
        # Check if CP exists and is available
        if request.cp_id not in self.charging_points:
            await self._send_driver_update(
                request,
                MessageStatus.DENIED,
                "Charging point not found"
            )
            return
        
        cp = self.charging_points[request.cp_id]
        
        # Security check: Verify CP is authorized
        if not cp.is_security_authorized():
            logger.warning(
                f"Driver request denied: CP {request.cp_id} not authorized "
                f"(auth={cp.is_authenticated}, status={cp.security_status.value})"
            )
            await self._send_driver_update(
                request,
                MessageStatus.DENIED,
                f"Charging point not authorized (status: {cp.security_status.value})"
            )
            return
        
        if not cp.is_available():
            await self._send_driver_update(
                request,
                MessageStatus.DENIED,
                f"Charging point not available (state: {cp.state})"
            )
            return
        
        # Accept the request
        self.active_requests[request.request_id] = request
        cp.current_driver = request.driver_id
        cp.current_session = generate_id("session")
        
        logger.info(f"Accepting request {request.request_id}: session_id={cp.current_session}, cp={request.cp_id}")
        
        # Start charging session in database
        try:
            self.db.start_charging_session(
                session_id=cp.current_session,
                cp_id=request.cp_id,
                driver_id=request.driver_id
            )
            logger.info(f"Charging session recorded in database: {cp.current_session}")
        except Exception as e:
            logger.error(f"Failed to record charging session in database: {e}")
            # Continue anyway - database is not critical for operation
        
        logger.info(f"Sending ACCEPTED update to driver {request.driver_id} with session_id={cp.current_session}")
        
        try:
            await self._send_driver_update(
                request,
                MessageStatus.ACCEPTED,
                "Request accepted, starting charging",
                session_id=cp.current_session
            )
            logger.info(f"ACCEPTED update sent successfully to {request.driver_id}")
        except Exception as e:
            logger.error(f"Failed to send ACCEPTED update: {e}")
        
        # Send START_SUPPLY command to CP_E
        command = CentralCommand(
            cmd=CommandType.START_SUPPLY,
            cp_id=request.cp_id,
            payload={
                "driver_id": request.driver_id,
                "request_id": request.request_id,
                "session_id": cp.current_session
            }
        )
        await self._send_encrypted_command(request.cp_id, command)
        logger.info(f"Sent START_SUPPLY command for CP {request.cp_id}")
    
    async def _send_encrypted_command(self, cp_id: str, command: CentralCommand):
        """
        Send an encrypted command to a CP via Kafka.
        
        If encryption is enabled and fails, the error is recorded and displayed
        on the CP's interface status.
        
        Args:
            cp_id: Target charging point
            command: Command to send
        """
        command_dict = json.loads(command.model_dump_json())
        
        if self.encrypted_kafka.encryption_enabled:
            # Encrypt the command
            encrypted_msg, error = self.encrypted_kafka.encrypt_message(cp_id, command_dict)
            
            if error:
                # Record error on CP for interface display
                if cp_id in self.charging_points:
                    self.charging_points[cp_id].set_encryption_error(
                        error.error_type.value,
                        error.message
                    )
                logger.error(
                    f"Failed to encrypt command for CP {cp_id}: {error.message}. "
                    "Command NOT sent - fix encryption key and retry."
                )
                return
            
            # Clear any previous encryption error (recovery)
            if cp_id in self.charging_points:
                self.charging_points[cp_id].clear_encryption_error()
            
            await self.producer.send(TOPICS["CENTRAL_COMMANDS"], encrypted_msg, key=cp_id)
        else:
            # Send unencrypted (lab/dev mode)
            await self.producer.send(TOPICS["CENTRAL_COMMANDS"], command, key=cp_id)

    async def handle_cp_status(self, status: CPStatus):
        """Process CP status updates."""
        cp_id = status.cp_id
        
        if cp_id not in self.charging_points:
            logger.warning(f"Status from unknown CP: {cp_id}")
            return
        
        cp = self.charging_points[cp_id]
        old_state = cp.state
        try:
            cp.state = CPState(status.state)
        except ValueError:
            logger.error(f"Invalid CP state '{status.state}' from {cp_id}")
            return
        cp.engine_status_known = True
        cp.last_seen = utc_now()
        cp.last_update = cp.last_seen
        
        # Record health snapshot to database
        self.db.record_health_snapshot(
            cp_id=cp_id,
            is_healthy=not cp.is_faulty,
            state=cp.state.value,
            circuit_state=cp.circuit_breaker.get_state().value
        )
        
        logger.debug(
            f"Status from {cp_id}: {cp.state.value} (was {old_state.value})"
        )
        
        # Handle state transitions
        await self._handle_state_transition(cp_id, old_state, cp)
    
    async def _handle_state_transition(self, cp_id: str, old_state: CPState, cp: ChargingPoint):
        """Handle state transitions for charging points."""
        # Session ended - transition from SUPPLYING to any other state
        if old_state == CPState.SUPPLYING and cp.state != CPState.SUPPLYING:
            if cp.current_session:
                # End the session in database
                if cp.last_telemetry:
                    self.db.end_charging_session(
                        session_id=cp.current_session,
                        total_kwh=cp.last_telemetry.kwh,
                        total_cost=cp.last_telemetry.euros,
                        status="COMPLETED" if cp.state == CPState.ACTIVATED else "FAILED"
                    )
                
                # Notify driver
                if cp.current_driver:
                    for req_id, req in list(self.active_requests.items()):
                        if req.cp_id == cp_id and req.driver_id == cp.current_driver:
                            if cp.state == CPState.ACTIVATED:
                                await self._send_driver_update(
                                    req,
                                    MessageStatus.COMPLETED,
                                    "Charging completed successfully"
                                )
                            else:
                                await self._send_driver_update(
                                    req,
                                    MessageStatus.FAILED,
                                    f"Charging interrupted: {cp.state.value}"
                                )
                            del self.active_requests[req_id]
                            break
                
                # Clear session
                cp.current_driver = None
                cp.current_session = None
                logger.info(f"Session ended on {cp_id}, state: {cp.state.value}")
    
    async def handle_cp_telemetry(self, telemetry: CPTelemetry):
        """Process CP telemetry updates."""
        cp_id = telemetry.cp_id
        
        if cp_id in self.charging_points:
            cp = self.charging_points[cp_id]
            cp.last_telemetry = telemetry
            
            # Update session energy in database if session is active
            if cp.current_session and telemetry.session_id == cp.current_session:
                self.db.update_session_energy(
                    session_id=cp.current_session,
                    kwh=telemetry.kwh,
                    cost=telemetry.euros
                )
            
            logger.debug(
                f"Telemetry from {cp_id}: {telemetry.kw:.2f} kW, "
                f"€{telemetry.euros:.2f}, driver={telemetry.driver_id}"
            )
            
            # Send progress update to driver
            if telemetry.driver_id:
                for req_id, req in self.active_requests.items():
                    if req.cp_id == cp_id and req.driver_id == telemetry.driver_id:
                        await self._send_driver_update(
                            req,
                            MessageStatus.IN_PROGRESS,
                            f"Charging: {telemetry.kw:.1f} kW, €{telemetry.euros:.2f}"
                        )
                        break

    async def handle_session_end(self, ticket: CPSessionTicket):
        driver_id = ticket.driver_id
        cp_id = ticket.cp_id
        session_id = ticket.session_id

        ticket_file = f"central_tickets/{driver_id}.txt"
        os.makedirs("central_tickets", exist_ok=True)

        with open(ticket_file, "a") as f:
            f.write(ticket.model_dump_json() + "\n")
        
        await self.producer.send(TOPICS["TICKET_TO_DRIVER"], ticket.model_dump(mode="json"), key=driver_id)

        logger.info(f"Saved final ticket for driver {driver_id} (session {session_id})")
        
        # Send COMPLETED update to driver
        # Find the original request for this session
        request_id = None
        for req_id, req in self.active_requests.items():
            if hasattr(req, 'driver_id') and req.driver_id == driver_id:
                if cp_id in self.charging_points:
                    cp = self.charging_points[cp_id]
                    if cp.current_session == session_id or cp.current_driver == driver_id:
                        request_id = req_id
                        break
        
        # Send COMPLETED status to driver
        update = DriverUpdate(
            request_id=request_id or generate_id("req"),  # Use found request_id or generate one
            driver_id=driver_id,
            cp_id=cp_id,
            status=MessageStatus.COMPLETED,
            reason=f"Session completed: {ticket.energy_kwh:.2f} kWh, €{ticket.total_cost_eur:.2f}",
            session_id=session_id
        )
        await self.producer.send(TOPICS["DRIVER_UPDATES"], update, key=driver_id)
        logger.info(f"Sent COMPLETED update to driver {driver_id} for session {session_id}")
        
        # Clear CP session info
        if cp_id in self.charging_points:
            cp = self.charging_points[cp_id]
            if cp.current_session == session_id:
                cp.current_session = None
                cp.current_driver = None
                logger.info(f"Cleared session info from CP {cp_id}")
        
        # Remove from active requests
        if request_id and request_id in self.active_requests:
            del self.active_requests[request_id]
            logger.info(f"Removed request {request_id} from active requests")

    
    async def _send_driver_update(
        self,
        request: DriverRequest,
        status: MessageStatus,
        reason: str,
        session_id: Optional[str] = None
    ):
        """Send status update to driver."""
        update = DriverUpdate(
            request_id=request.request_id,
            driver_id=request.driver_id,
            cp_id=request.cp_id,
            status=status,
            reason=reason,
            session_id=session_id
        )
        await self.producer.send(TOPICS["DRIVER_UPDATES"], update, key=request.driver_id)
        logger.info(f"Sent {status.value} update to driver {request.driver_id} for {request.cp_id} (session_id: {session_id})")
    
    async def send_stop_supply_command(self, cp_id: str, reason: str = "Manual stop requested"):
        """Send STOP_SUPPLY command to a charging point."""
        if cp_id not in self.charging_points:
            logger.error(f"Cannot send stop command to unknown CP: {cp_id}")
            return
        
        command = CentralCommand(
            cmd=CommandType.STOP_SUPPLY,
            cp_id=cp_id,
            payload={"reason": reason}
        )
        await self._send_encrypted_command(cp_id, command)
        logger.info(f"Sent STOP_SUPPLY command to {cp_id}: {reason}")
    
    def _try_decrypt_cp_message(self, value: dict) -> tuple[dict | None, str | None]:
        """
        Try to decrypt a message from a CP.
        
        Args:
            value: Raw message from Kafka
            
        Returns:
            Tuple of (decrypted payload, cp_id) or (None, None) on failure
        """
        if not isinstance(value, dict):
            return value, None
        
        # Check if message is in encrypted format
        if "encrypted" not in value or "cp_id" not in value:
            # Not an encrypted message wrapper - return as-is
            return value, value.get("cp_id")
        
        cp_id = value.get("cp_id")
        encrypted = value.get("encrypted", False)
        payload = value.get("payload")
        
        if not encrypted:
            # Unencrypted wrapper - return payload directly
            if isinstance(payload, dict):
                return payload, cp_id
            if isinstance(payload, str):
                import json
                return json.loads(payload), cp_id
            return payload, cp_id
        
        # Message is encrypted - try to decrypt
        if not self.encrypted_kafka.encryption_enabled:
            # Encryption disabled on Central but CP sent encrypted message
            logger.warning(
                f"Received encrypted message from CP {cp_id} but encryption is disabled. "
                "Enable encryption or reconfigure CP."
            )
            return None, cp_id
        
        decrypted, error = self.encrypted_kafka.decrypt_message(value)
        
        if error:
            # Record error on CP for interface display
            if cp_id in self.charging_points:
                self.charging_points[cp_id].set_encryption_error(
                    error.error_type.value,
                    error.message
                )
            return None, cp_id
        
        # Clear any previous error (recovery)
        if cp_id in self.charging_points:
            self.charging_points[cp_id].clear_encryption_error()
        
        return decrypted, cp_id
    
    async def process_messages(self):
        """Main message processing loop with resilient error handling."""
        logger.info("Starting message processing loop...")
        
        while self._running:
            try:
                async for msg in self.consumer.consume():
                    if not self._running:
                        break
                    
                    try:
                        topic = msg["topic"]
                        value = msg["value"]
                        
                        # Use asyncio.wait_for to prevent any single message from blocking too long
                        await asyncio.wait_for(
                            self._process_single_message(topic, value),
                            timeout=10.0  # 10 second timeout per message
                        )
                        
                    except asyncio.TimeoutError:
                        logger.error(f"Timeout processing message from {msg.get('topic')} - skipping")
                        continue
                    except Exception as e:
                        logger.error(f"Error processing message from {msg.get('topic')}: {e}")
                        # Report message processing error
                        self.error_manager.report_error(
                            category=ErrorCategory.COMMUNICATION,
                            source=ErrorSource.CENTRAL,
                            target=msg.get('topic', 'Unknown'),
                            message=f"Error processing message. Messages are incomprehensible.",
                            severity=ErrorSeverity.ERROR,
                            technical_detail=str(e)
                        )
                        continue
                        
            except asyncio.CancelledError:
                logger.info("Message processing cancelled")
                break
            except Exception as e:
                logger.error(f"Consumer error: {e} - attempting to continue...")
                # Brief pause before retry to avoid tight loop on persistent errors
                await asyncio.sleep(1.0)
                continue
        
        logger.info("Message processing loop stopped")
    
    async def _process_single_message(self, topic: str, value: dict):
        """Process a single Kafka message. Extracted for timeout handling."""
        if topic == TOPICS["DRIVER_REQUESTS"]:
            # Driver requests are NOT encrypted (from driver app)
            request = DriverRequest(**value)
            await self.handle_driver_request(request)
        
        elif topic == TOPICS["CP_STATUS"]:
            # Try to decrypt if encrypted
            decrypted, cp_id = self._try_decrypt_cp_message(value)
            if decrypted is None:
                logger.error(f"Failed to decrypt CP_STATUS from {cp_id}")
                # Report error for dashboard display
                report_communication_error(
                    source=ErrorSource.CENTRAL,
                    target=cp_id or "Unknown CP",
                    component=f"CP {cp_id or 'Unknown'}",
                    detail="Failed to decrypt or parse CP_STATUS message"
                )
                return
            status = CPStatus(**decrypted)
            await self.handle_cp_status(status)
        
        elif topic == TOPICS["CP_TELEMETRY"]:
            # Try to decrypt if encrypted
            decrypted, cp_id = self._try_decrypt_cp_message(value)
            if decrypted is None:
                logger.error(f"Failed to decrypt CP_TELEMETRY from {cp_id}")
                # Report error for dashboard display
                report_communication_error(
                    source=ErrorSource.CENTRAL,
                    target=cp_id or "Unknown CP",
                    component=f"CP {cp_id or 'Unknown'}",
                    detail="Failed to decrypt or parse CP_TELEMETRY message"
                )
                return
            telemetry = CPTelemetry(**decrypted)
            await self.handle_cp_telemetry(telemetry)
        
        elif topic == TOPICS["CP_SESSION_END"]:
            logger.warning("=== CENTRAL received SESSION_END event")
            # Try to decrypt if encrypted
            decrypted, cp_id = self._try_decrypt_cp_message(value)
            if decrypted is None:
                logger.error(f"Failed to decrypt CP_SESSION_END from {cp_id}")
                # Report error for dashboard display
                report_communication_error(
                    source=ErrorSource.CENTRAL,
                    target=cp_id or "Unknown CP",
                    component=f"CP {cp_id or 'Unknown'}",
                    detail="Failed to decrypt or parse CP_SESSION_END message"
                )
                return
            ticket = CPSessionTicket(**decrypted)
            await self.handle_session_end(ticket)
    
    def get_dashboard_data(self) -> dict:
        """Get current state for dashboard display."""
        self._refresh_monitor_states()
        return {
            "charging_points": [
                {
                    "cp_id": cp.cp_id,
                    "state": cp.get_display_state(),
                    "engine_state": cp.state.value,
                    "monitor_status": cp.monitor_status.value,
                    "city": cp.city,
                    "weather": self.weather_by_city.get(cp.city),
                    "current_driver": cp.current_driver,
                    "current_session": cp.current_session,
                    "last_update": cp.last_update.isoformat(),
                    "monitor_last_seen": cp.monitor_last_seen.isoformat() if cp.monitor_last_seen else None,
                    "security_status": cp.security_status.value,
                    "is_authenticated": cp.is_authenticated,
                    "has_encryption_key": cp.has_encryption_key,
                    # Encryption error display for interface
                    "communication_status": cp.communication_status,
                    "encryption_error": cp.encryption_error,
                    "encryption_error_type": cp.encryption_error_type,
                    "encryption_error_timestamp": (
                        cp.encryption_error_timestamp.isoformat() 
                        if cp.encryption_error_timestamp else None
                    ),
                    # Fault status for display
                    "is_faulty": cp.is_faulty,
                    "fault_reason": cp.fault_reason,
                    "telemetry": (
                        {
                            "kw": cp.last_telemetry.kw,
                            "kwh": cp.last_telemetry.kwh,
                            "euros": cp.last_telemetry.euros,
                            "session_id": cp.last_telemetry.session_id,
                        }
                        if cp.last_telemetry
                        else None
                    ),
                }
                for cp in self.charging_points.values()
            ],
            # Include global encryption error summary
            "encryption_errors": self.encryption_error_tracker.get_error_list(),
            "active_requests": len(self.active_requests),
            "active_requests_details": [
                {
                    "request_id": req.request_id,
                    "driver_id": req.driver_id,
                    "cp_id": req.cp_id,
                    "ts": req.ts.isoformat(),
                }
                for req in self.active_requests.values()
            ],
            # System events for restoration/failure tracking
            "system_events": self.system_events[:20],  # Last 20 events for dashboard
            # Centralized error tracking
            "system_errors": self.error_manager.get_errors_for_display(limit=30),
            "error_summary": self.error_manager.get_error_summary(),
        }

    def _refresh_monitor_states(self):
        """Mark monitors as down when heartbeat timeout is exceeded."""
        now = utc_now()
        for cp in self.charging_points.values():
            if not cp.monitor_last_seen:
                if cp.monitor_status != ChargingPoint.MonitorStatus.DOWN:
                    # First time marking as down - add system event
                    self._add_system_event(
                        "FAILURE",
                        cp.cp_id,
                        f"CP {cp.cp_id} monitor connection lost (no heartbeat received)",
                        "WARNING"
                    )
                cp.mark_monitor_down()
                # If monitor is down, engine status is unknown
                if cp.state != CPState.DISCONNECTED:
                    cp.state = CPState.DISCONNECTED
                    cp.engine_status_known = False
                    cp.last_update = now
                continue
            if now - cp.monitor_last_seen > self.monitor_timeout:
                if cp.monitor_status != ChargingPoint.MonitorStatus.DOWN:
                    # First time marking as down due to timeout - add system event
                    self._add_system_event(
                        "FAILURE",
                        cp.cp_id,
                        f"CP {cp.cp_id} monitor heartbeat timeout - connection lost",
                        "WARNING"
                    )
                cp.mark_monitor_down()
                # If monitor heartbeat timed out, engine status is unknown
                if cp.state != CPState.DISCONNECTED:
                    cp.state = CPState.DISCONNECTED
                    cp.engine_status_known = False
                    cp.last_update = now


# Global controller instance for dashboard access
_controller: EVCentralController | None = None


def get_controller() -> EVCentralController:
    """Get the global controller instance."""
    if _controller is None:
        raise RuntimeError("Controller not initialized")
    return _controller


async def main():
    """Main entry point for EV Central service."""
    parser = argparse.ArgumentParser(description="EV Central Controller")
    parser.add_argument("--listen-port", type=int, help="TCP control plane port")
    parser.add_argument("--http-port", type=int, help="HTTP dashboard port")
    parser.add_argument("--kafka-bootstrap", type=str, help="Kafka bootstrap servers")
    parser.add_argument("--db-url", type=str, help="Database URL (optional)")
    parser.add_argument("--log-level", type=str, default="INFO", help="Log level")
    
    args = parser.parse_args()
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>Central</cyan> | <level>{message}</level>",
        level=args.log_level
    )
    
    # Build config from args
    config_dict = {k: v for k, v in vars(args).items() if v is not None}
    config = CentralConfig(**config_dict)
    
    # Initialize controller
    global _controller
    _controller = EVCentralController(config)
    
    try:
        await _controller.start()
        
        # Start TCP control server
        tcp_server = TCPControlServer(config.listen_port)
        tcp_task = asyncio.create_task(tcp_server.start())
        
        # Start dashboard (in separate thread via uvicorn)
        from uvicorn import Config, Server
        dashboard_app = create_dashboard_app(_controller)
        uvicorn_config = Config(
            dashboard_app,
            host="0.0.0.0",
            port=config.http_port,
            log_level=config.log_level.lower()
        )
        server = Server(uvicorn_config)
        server_task = asyncio.create_task(server.serve())
        
        # Start message processing
        processing_task = asyncio.create_task(_controller.process_messages())

        #komentarz
        #logger.info(f"Dashboard available at http://localhost:{config.http_port}")
        #logger.info(f"TCP control server listening on port {config.listen_port}")
        
        # Wait for all tasks
        await asyncio.gather(tcp_task, server_task, processing_task)
    
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        # Cleanup tasks and servers
        if 'tcp_server' in locals():
            await tcp_server.stop()
        if 'tcp_task' in locals() and not tcp_task.done():
            tcp_task.cancel()
            try:
                await tcp_task
            except asyncio.CancelledError:
                pass
        if 'server_task' in locals() and not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
        await _controller.stop()


if __name__ == "__main__":
    asyncio.run(main())
