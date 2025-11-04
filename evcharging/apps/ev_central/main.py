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
from enum import Enum
from typing import Dict, Optional
from datetime import datetime, timedelta
from loguru import logger

from evcharging.common.config import CentralConfig, TOPICS
from evcharging.common.kafka import KafkaProducerHelper, KafkaConsumerHelper, ensure_topics
from evcharging.common.messages import (
    DriverRequest, DriverUpdate, MessageStatus, CentralCommand, CommandType,
    CPStatus, CPTelemetry, CPRegistration
)
from evcharging.common.states import CPState, can_supply
from evcharging.common.utils import utc_now, generate_id
from evcharging.common.circuit_breaker import CircuitBreaker, CircuitState
from evcharging.common.database import FaultHistoryDB

from evcharging.apps.ev_central.dashboard import create_dashboard_app
from evcharging.apps.ev_central.tcp_server import TCPControlServer


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
        self.monitor_status: ChargingPoint.MonitorStatus = ChargingPoint.MonitorStatus.DOWN
        self.monitor_last_seen: datetime | None = None
        self.engine_status_known: bool = False
    
    def is_available(self) -> bool:
        """Check if CP is available for new charging session."""
        # Check circuit breaker state
        if self.circuit_breaker.get_state() == CircuitState.OPEN:
            return False
        
        return can_supply(self.state) and self.current_driver is None and not self.is_faulty

    def record_monitor_heartbeat(self):
        """Record heartbeat received from monitor."""
        self.monitor_last_seen = utc_now()
        self.monitor_status = ChargingPoint.MonitorStatus.OK

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
    
    async def start(self):
        """Initialize and start the central controller."""
        logger.info("Starting EV Central Controller...")
        
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
            topics=[TOPICS["DRIVER_REQUESTS"], TOPICS["CP_STATUS"], TOPICS["CP_TELEMETRY"]],
            group_id="central-controller",
            auto_offset_reset="latest"
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
        self.charging_points[cp_id].state = CPState.ACTIVATED
        self.charging_points[cp_id].last_update = utc_now()
        self.charging_points[cp_id].record_monitor_heartbeat()
        
        return True
    
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
                await self.producer.send(TOPICS["CENTRAL_COMMANDS"], command, key=cp_id)
                logger.info(f"Sent STOP_CP command to {cp_id} due to fault: {reason}")
            except Exception as e:
                logger.error(f"Failed to send STOP_CP command to {cp_id}: {e}")
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
            cp.record_monitor_heartbeat()
        else:
            logger.warning(f"Heartbeat from unregistered CP monitor: {cp_id} - creating and activating placeholder entry")
            # Create placeholder and immediately activate it since monitor is alive
            cp = ChargingPoint(cp_id)
            cp.state = CPState.ACTIVATED  # Set to ACTIVATED instead of DISCONNECTED
            cp.record_monitor_heartbeat()
            self.charging_points[cp_id] = cp
            
            # Log the auto-registration
            logger.info(f"CP {cp_id} auto-registered via monitor heartbeat - state: ACTIVATED")

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
        
        # Start charging session in database
        self.db.start_charging_session(
            session_id=cp.current_session,
            cp_id=request.cp_id,
            driver_id=request.driver_id
        )
        
        await self._send_driver_update(
            request,
            MessageStatus.ACCEPTED,
            "Request accepted, starting charging",
            session_id=cp.current_session
        )
        
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
        await self.producer.send(TOPICS["CENTRAL_COMMANDS"], command, key=request.cp_id)
        logger.info(f"Sent START_SUPPLY command for CP {request.cp_id}")
    
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
        await self.producer.send(TOPICS["CENTRAL_COMMANDS"], command, key=cp_id)
        logger.info(f"Sent STOP_SUPPLY command to {cp_id}: {reason}")
    
    async def process_messages(self):
        """Main message processing loop."""
        async for msg in self.consumer.consume():
            try:
                topic = msg["topic"]
                value = msg["value"]
                
                if topic == TOPICS["DRIVER_REQUESTS"]:
                    request = DriverRequest(**value)
                    await self.handle_driver_request(request)
                
                elif topic == TOPICS["CP_STATUS"]:
                    status = CPStatus(**value)
                    await self.handle_cp_status(status)
                
                elif topic == TOPICS["CP_TELEMETRY"]:
                    telemetry = CPTelemetry(**value)
                    await self.handle_cp_telemetry(telemetry)
            
            except Exception as e:
                logger.error(f"Error processing message from {msg.get('topic')}: {e}")
    
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
                    "current_driver": cp.current_driver,
                    "last_update": cp.last_update.isoformat(),
                    "monitor_last_seen": cp.monitor_last_seen.isoformat() if cp.monitor_last_seen else None,
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
            "active_requests": len(self.active_requests),
        }

    def _refresh_monitor_states(self):
        """Mark monitors as down when heartbeat timeout is exceeded."""
        now = utc_now()
        for cp in self.charging_points.values():
            if not cp.monitor_last_seen:
                cp.mark_monitor_down()
                # If monitor is down, engine status is unknown
                if cp.state != CPState.DISCONNECTED:
                    cp.state = CPState.DISCONNECTED
                    cp.engine_status_known = False
                    cp.last_update = now
                continue
            if now - cp.monitor_last_seen > self.monitor_timeout:
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
        
        logger.info(f"Dashboard available at http://localhost:{config.http_port}")
        logger.info(f"TCP control server listening on port {config.listen_port}")
        
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
