"""
EV CP Engine - Charging Point Engine service.

Responsibilities:
- Execute charging operations
- Manage CP state machine
- Emit telemetry during charging sessions
- Respond to Central commands
- Provide health check endpoint for CP Monitor
"""

import asyncio
import argparse
import sys
import os
from datetime import datetime
import json
from loguru import logger

from evcharging.common.config import CPEngineConfig, TOPICS
from evcharging.common.kafka import KafkaProducerHelper, KafkaConsumerHelper, ensure_topics
from evcharging.common.messages import (
    CentralCommand, CPStatus, CPTelemetry, CommandType, CPSessionTicket
)
from evcharging.common.states import CPState, CPEvent, transition, StateTransitionError
from evcharging.common.utils import utc_now
from evcharging.common.cp_security import CPEncryptionService
from evcharging.common.error_manager import (
    ErrorManager, ErrorCategory, ErrorSeverity, ErrorSource,
    get_error_manager, report_connection_error, report_communication_error,
    report_registry_error, resolve_target_errors
)


class ChargingSession:
    """Represents an active charging session."""
    
    def __init__(self, session_id: str, driver_id: str, request_id: str):
        self.session_id = session_id
        self.driver_id = driver_id
        self.request_id = request_id
        self.start_time = utc_now()
        self.cumulative_kwh = 0.0
        self.cumulative_euros = 0.0


class CPEngine:
    """Charging Point Engine managing state and operations."""
    
    def __init__(self, config: CPEngineConfig):
        self.config = config
        self.cp_id = config.cp_id
        self.state = CPState.DISCONNECTED  # Start in DISCONNECTED, will transition to ACTIVATED
        self.producer: KafkaProducerHelper | None = None
        self.consumer: KafkaConsumerHelper | None = None
        self.current_session: ChargingSession | None = None
        self.telemetry_task: asyncio.Task | None = None
        self.health_server: asyncio.Server | None = None
        self._running = False
        self.start_time = 0.0  # Track startup time for demo mode
        
        # Encryption support
        self._encryption_key: bytes | None = None
        self._encryption_enabled = os.environ.get("EV_KAFKA_ENCRYPTION", "false").lower() == "true"
        self._encryption_error: str | None = None
        self._encryption_error_type: str | None = None
        
        # Initialize error manager for tracking and display
        self.error_manager = get_error_manager()
        
        # Central connectivity tracking
        self._central_connected: bool = True
        self._central_error: str | None = None
        self._message_errors: list[dict] = []  # Track recent message errors for display
        
        # Load encryption key from environment or file
        self._load_encryption_key()
    
    async def _send_encrypted_message(self, topic: str, message_obj, key: str):
        """
        Send an encrypted message to Kafka.
        
        If encryption is enabled, wraps the message in an encrypted envelope.
        If encryption fails, logs error and message is NOT sent to prevent
        unencrypted data leakage.
        
        Args:
            topic: Kafka topic to send to
            message_obj: Pydantic model or dict to send
            key: Kafka message key
        """
        import base64
        from pydantic import BaseModel
        
        # Convert to dict if needed
        if isinstance(message_obj, BaseModel):
            message_dict = json.loads(message_obj.model_dump_json())
        elif isinstance(message_obj, dict):
            message_dict = message_obj
        else:
            logger.error(f"CP {self.cp_id}: Invalid message type for encryption")
            return
        
        if not self._encryption_enabled:
            # Send unencrypted (lab mode)
            await self.producer.send(topic, message_obj, key=key)
            return
        
        if not self._encryption_key:
            self._set_encryption_error(
                "key_not_found",
                f"Cannot send encrypted message: No encryption key loaded for CP {self.cp_id}"
            )
            # DO NOT send unencrypted - this would be a security breach
            logger.error(
                f"CP {self.cp_id}: Message NOT sent to {topic} - no encryption key. "
                "Fix encryption key and restart."
            )
            return
        
        try:
            # Encrypt the payload
            payload_json = json.dumps(message_dict)
            encrypted_payload = CPEncryptionService.encrypt_payload(payload_json, self._encryption_key)
            
            # Create encrypted message wrapper
            encrypted_message = {
                "cp_id": self.cp_id,
                "encrypted": True,
                "payload": encrypted_payload,
                "ts": utc_now().isoformat()
            }
            
            await self.producer.send(topic, encrypted_message, key=key)
            
            # Clear any previous error (recovery)
            if self._encryption_error:
                logger.info(f"CP {self.cp_id}: Encryption recovered - sending messages successfully")
                self._clear_encryption_error()
        
        except Exception as e:
            self._set_encryption_error(
                "encryption_failed",
                f"Failed to encrypt message for {topic}: {str(e)}"
            )
            # DO NOT send unencrypted
            logger.error(
                f"CP {self.cp_id}: Message NOT sent to {topic} - encryption failed: {e}"
            )
    
    async def start(self):
        """Initialize and start the CP Engine."""
        logger.info(f"Starting CP Engine: {self.cp_id}")
        
        try:
            # Ensure Kafka topics exist
            await ensure_topics(
                self.config.kafka_bootstrap,
                list(TOPICS.values())
            )
            
            # Initialize Kafka producer
            self.producer = KafkaProducerHelper(self.config.kafka_bootstrap)
            await self.producer.start()
            
            # Initialize Kafka consumer for commands
            self.consumer = KafkaConsumerHelper(
                self.config.kafka_bootstrap,
                topics=[TOPICS["CENTRAL_COMMANDS"]],
                group_id=f"cp-engine-{self.cp_id}",
                auto_offset_reset="latest"
            )
            await self.consumer.start()
            
            # Clear any previous Central connection errors
            resolve_target_errors("Central", "Kafka connection established successfully")
            
        except Exception as e:
            logger.error(f"CP {self.cp_id}: Failed to connect to Kafka/Central: {e}")
            report_connection_error(
                source=ErrorSource.CP_ENGINE,
                target="Central",
                service_name="Central",
                detail=f"Impossible to connect to Central: {e}"
            )
            raise
        
        # Start health check TCP server
        await self.start_health_server()
        
        # Auto-activate CP for immediate availability
        await self.change_state(CPEvent.CONNECT, "Engine started - auto-connecting")

        # Resend any exisiting tickets from the txt file to the Central
        await self.resend_stored_tickets()
        
        # Record startup time for demo mode (ignore STOP commands for first 10 seconds)
        import time
        self.start_time = time.time()
        
        self._running = True
        logger.info(f"CP Engine {self.cp_id} started successfully")
    
    async def stop(self):
        """Stop the CP Engine gracefully."""
        logger.info(f"Stopping CP Engine: {self.cp_id}")
        self._running = False
        
        # Stop telemetry if running
        if self.telemetry_task and not self.telemetry_task.done():
            self.telemetry_task.cancel()
            try:
                await self.telemetry_task
            except asyncio.CancelledError:
                pass
        
        # Transition to DISCONNECTED
        try:
            await self.change_state(CPEvent.DISCONNECT, "Engine shutting down")
        except StateTransitionError:
            pass
        
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        
        if self.health_server:
            self.health_server.close()
            await self.health_server.wait_closed()
        
        logger.info(f"CP Engine {self.cp_id} stopped")
    
    async def change_state(self, event: CPEvent, reason: str = ""):
        """Transition CP state and notify Central."""
        try:
            old_state = self.state
            context = {"authorized": True, "vehicle_plugged": True}  # Simulated
            self.state = transition(self.state, event, context)
            
            logger.info(f"CP {self.cp_id}: {old_state} + {event} -> {self.state} ({reason})")
            
            # Send status update to Central (encrypted if enabled)
            status = CPStatus(
                cp_id=self.cp_id,
                state=self.state.value,
                reason=reason or f"Event: {event}"
            )
            await self._send_encrypted_message(TOPICS["CP_STATUS"], status, key=self.cp_id)
        
        except StateTransitionError as e:
            logger.error(f"Invalid state transition: {e}")
            raise
    
    async def handle_command(self, command: CentralCommand):
        """Process command from Central."""
        if command.cp_id != self.cp_id:
            return  # Not for this CP
        
        logger.info(f"CP {self.cp_id} received command: {command.cmd}")
        
        try:
            if command.cmd == CommandType.START_SUPPLY:
                await self.start_supply(command.payload)
            
            elif command.cmd == CommandType.STOP_SUPPLY:
                await self.stop_supply("Central requested stop")
            
            elif command.cmd == CommandType.STOP_CP:
                # Demo mode: Ignore STOP_CP commands during first 10 seconds after startup
                import time
                if time.time() - self.start_time < 10:
                    logger.info(f"CP {self.cp_id}: Ignoring STOP_CP during startup grace period (demo mode)")
                    return
                await self.change_state(CPEvent.STOP_CP, "Central stopped CP")
            
            elif command.cmd == CommandType.RESUME_CP:
                await self.change_state(CPEvent.RESUME_CP, "Central resumed CP")
            
            elif command.cmd == CommandType.SHUTDOWN:
                logger.info(f"CP {self.cp_id}: Received SHUTDOWN command")
                self._running = False
                await self.stop()
        
        except StateTransitionError as e:
            logger.error(f"Failed to execute command {command.cmd}: {e}")
    
    async def start_supply(self, payload: dict):
        """Start charging session."""
        # Validate payload
        if not payload or not isinstance(payload, dict):
            logger.error(f"CP {self.cp_id}: Invalid payload for START_SUPPLY command")
            return
        
        driver_id = payload.get("driver_id")
        request_id = payload.get("request_id")
        session_id = payload.get("session_id")
        
        if not driver_id:
            logger.error("START_SUPPLY command missing driver_id")
            return
        
        # Transition to SUPPLYING state
        await self.change_state(
            CPEvent.START_SUPPLY,
            f"Starting supply for driver {driver_id}"
        )
        
        # Create charging session
        self.current_session = ChargingSession(session_id, driver_id, request_id)
        
        # Start telemetry emission
        self.telemetry_task = asyncio.create_task(self.emit_telemetry())
        logger.info(f"CP {self.cp_id}: Charging session started for {driver_id}")
    
    async def stop_supply(self, reason: str):
        """Stop current charging session."""
        if self.state != CPState.SUPPLYING:
            logger.warning(f"CP {self.cp_id}: Cannot stop supply, not in SUPPLYING state")
            return

        logger.warning("=== Engine STOP SUPPLY called")
        
        # Stop telemetry
        if self.telemetry_task and not self.telemetry_task.done():
            self.telemetry_task.cancel()
            try:
                await self.telemetry_task
            except asyncio.CancelledError:
                pass
        
        # Log session summary
        if self.current_session:
            logger.info(
                f"CP {self.cp_id}: Session {self.current_session.session_id} completed. "
                f"Total: {self.current_session.cumulative_kwh:.2f} kWh, "
                f"€{self.current_session.cumulative_euros:.2f}"
            )

            ticket = CPSessionTicket (
                cp_id=self.cp_id,
                session_id=self.current_session.session_id,
                driver_id=self.current_session.driver_id,
                start_time=self.current_session.start_time,
                end_time=utc_now(),
                energy_kwh=self.current_session.cumulative_kwh,
                total_cost_eur=self.current_session.cumulative_euros,
            )

            ticket_file = f"tickets/{self.cp_id}.txt"
            os.makedirs("tickets", exist_ok=True)
            with open(ticket_file, "a") as f:
                f.write(ticket.model_dump_json() + "\n")
            
            try:
                await self._send_encrypted_message(TOPICS["CP_SESSION_END"], ticket.model_dump(mode="json"), key=self.cp_id)
                logger.warning("=== Sent CP_SESSION_END event")
            except Exception as e:
                logger.warning(f"CP {self.cp_id}: Failed to notify Central — will retry later ({e})")
            
            logger.info(f"CP {self.cp_id}: Stored final ticket for {self.current_session.driver_id}")

        
        # Transition back to ACTIVATED
        await self.change_state(CPEvent.STOP_SUPPLY, reason)
        self.current_session = None

    async def resend_stored_tickets(self):
        ticket_dir = "tickets"
        if not os.path.exists(ticket_dir):
            return
        for file_name in os.listdir(ticket_dir):
            with open(os.path.join(ticket_dir, file_name)) as f:
                for line in f:
                    ticket = json.loads(line.strip())
                    try:
                        await self._send_encrypted_message(TOPICS["CP_SESSION_END"], ticket, key=self.cp_id)
                        logger.info(f"Resent stored ticket for {ticket['driver_id']}")
                    except Exception as e:
                        logger.warning(f"Failed to resend ticket {ticket['session_id']}: {e}")

    
    async def emit_telemetry(self):
        """Emit telemetry data during charging session."""
        try:
            while self.state == CPState.SUPPLYING and self.current_session:
                # Simulate power delivery
                elapsed = (utc_now() - self.current_session.start_time).total_seconds()
                
                # Calculate cumulative values
                # kWh = kW * hours
                kwh_increment = (self.config.kw_rate * self.config.telemetry_interval) / 3600
                self.current_session.cumulative_kwh += kwh_increment
                self.current_session.cumulative_euros = (
                    self.current_session.cumulative_kwh * self.config.euro_rate
                )
                
                # Emit telemetry (encrypted if enabled)
                telemetry = CPTelemetry(
                    cp_id=self.cp_id,
                    kw=self.config.kw_rate,
                    kwh=self.current_session.cumulative_kwh,
                    euros=self.current_session.cumulative_euros,
                    driver_id=self.current_session.driver_id,
                    session_id=self.current_session.session_id
                )
                await self._send_encrypted_message(TOPICS["CP_TELEMETRY"], telemetry, key=self.cp_id)
                
                logger.debug(
                    f"CP {self.cp_id} telemetry: {telemetry.kw:.2f} kW, "
                    f"€{telemetry.euros:.2f}"
                )
                
                await asyncio.sleep(self.config.telemetry_interval)
                
                # Optional: Check for session timeout (if configured)
                if self.config.max_session_seconds is not None and elapsed > self.config.max_session_seconds:
                    logger.info(f"CP {self.cp_id}: Session time limit reached ({self.config.max_session_seconds}s)")
                    await self.stop_supply("Session time limit reached")
                    break
        
        except asyncio.CancelledError:
            logger.debug(f"CP {self.cp_id}: Telemetry task cancelled")
        except Exception as e:
            logger.error(f"CP {self.cp_id}: Error in telemetry loop: {e}")
            await self.change_state(CPEvent.FAULT_DETECTED, f"Telemetry error: {e}")
    
    async def start_health_server(self):
        """Start TCP health check server for CP Monitor."""
        async def handle_health_check(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            addr = writer.get_extra_info('peername')
            try:
                while True:
                    data = await reader.read(100)
                    if not data:
                        break
                    
                    # Respond with status including encryption error if any
                    if self._encryption_error:
                        response = f"ENCRYPTION_ERROR:{self.state.value}:{self._encryption_error_type}\n"
                    else:
                        # Include error count in response
                        active_errors = self.error_manager.get_active_errors(source=ErrorSource.CP_ENGINE)
                        error_count = len(active_errors)
                        if error_count > 0:
                            response = f"OK:{self.state.value}:ERRORS={error_count}\n"
                        else:
                            response = f"OK:{self.state.value}\n"
                    writer.write(response.encode('utf-8'))
                    await writer.drain()
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        
        self.health_server = await asyncio.start_server(
            handle_health_check,
            '0.0.0.0',
            self.config.health_port
        )
        logger.info(f"CP {self.cp_id}: Health server listening on port {self.config.health_port}")
    
    async def handle_fault(self, reason: str):
        """Handle fault condition from monitor."""
        logger.warning(f"CP {self.cp_id}: FAULT detected - {reason}")
        
        # Stop any active session
        if self.state == CPState.SUPPLYING:
            if self.telemetry_task and not self.telemetry_task.done():
                self.telemetry_task.cancel()
        
        # Transition to FAULT state
        await self.change_state(CPEvent.FAULT_DETECTED, reason)
        self.current_session = None
    
    async def clear_fault(self):
        """Clear fault and return to operational state."""
        if self.state == CPState.FAULT:
            await self.change_state(CPEvent.FAULT_CLEARED, "Fault cleared by monitor")
            logger.info(f"CP {self.cp_id}: Fault cleared, returning to ACTIVATED")
    
    async def process_messages(self):
        """Main message processing loop."""
        try:
            async for msg in self.consumer.consume():
                # Check if we should stop processing
                if not self._running:
                    logger.info(f"CP {self.cp_id}: Stopping message processing")
                    break
                
                try:
                    topic = msg["topic"]
                    value = msg["value"]
                    
                    if topic == TOPICS["CENTRAL_COMMANDS"]:
                        # Try to decrypt if message is encrypted
                        command_data = await self._try_decrypt_message(value)
                        
                        if command_data is None:
                            # Decryption failed - error already logged
                            # Report error for CP display
                            report_communication_error(
                                source=ErrorSource.CP_ENGINE,
                                target="Central",
                                component="Central",
                                detail="Failed to decrypt or parse command message from Central"
                            )
                            continue
                        
                        command = CentralCommand(**command_data)
                        await self.handle_command(command)
                        
                        # Clear any previous Central connection errors on success
                        resolve_target_errors("Central", "Successfully received command from Central")
                        
                        # Break loop if shutdown was commanded
                        if not self._running:
                            break
                
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    # Report message processing error
                    self.error_manager.report_error(
                        category=ErrorCategory.COMMUNICATION,
                        source=ErrorSource.CP_ENGINE,
                        target="Central",
                        message="Incomprehensible messages from the central office.",
                        severity=ErrorSeverity.ERROR,
                        technical_detail=str(e)
                    )
        except Exception as e:
            if self._running:  # Only log if not intentionally stopped
                logger.error(f"Error in message processing loop: {e}")
                # Report Kafka connection error
                report_connection_error(
                    source=ErrorSource.CP_ENGINE,
                    target="Central",
                    service_name="Central",
                    detail=f"Message processing loop error: {e}"
                )
    
    def _load_encryption_key(self):
        """
        Load encryption key from environment or key file.
        
        Key sources (in order of priority):
        1. EV_CP_ENCRYPTION_KEY environment variable (base64 encoded)
        2. Key file at path specified by EV_CP_KEY_FILE
        3. Default key file at ./keys/{cp_id}.key
        """
        import base64
        
        # Try environment variable first
        key_b64 = os.environ.get("EV_CP_ENCRYPTION_KEY")
        if key_b64:
            try:
                self._encryption_key = base64.b64decode(key_b64)
                logger.info(f"CP {self.cp_id}: Loaded encryption key from environment")
                return
            except Exception as e:
                logger.error(f"CP {self.cp_id}: Invalid key in EV_CP_ENCRYPTION_KEY: {e}")
        
        # Try key file
        key_file = os.environ.get("EV_CP_KEY_FILE", f"keys/{self.cp_id}.key")
        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    self._encryption_key = f.read()
                logger.info(f"CP {self.cp_id}: Loaded encryption key from {key_file}")
                return
            except Exception as e:
                logger.error(f"CP {self.cp_id}: Failed to read key file {key_file}: {e}")
        
        # No key available
        if self._encryption_enabled:
            logger.warning(
                f"CP {self.cp_id}: Encryption enabled but no key available. "
                f"Set EV_CP_ENCRYPTION_KEY or create key file at {key_file}"
            )
        else:
            logger.debug(f"CP {self.cp_id}: Encryption disabled, no key needed")
    
    async def _try_decrypt_message(self, message: dict) -> dict | None:
        """
        Try to decrypt an encrypted message.
        
        Args:
            message: Raw message from Kafka
            
        Returns:
            Decrypted payload dict, or original message if not encrypted,
            or None if decryption failed
        """
        # Check if message is in encrypted format
        if not isinstance(message, dict):
            return message
        
        # Check for encrypted message wrapper
        if "encrypted" not in message or "cp_id" not in message:
            # Not an encrypted message wrapper - return as-is
            return message
        
        cp_id = message.get("cp_id")
        encrypted = message.get("encrypted", False)
        payload = message.get("payload")
        
        # Check if message is for this CP
        if cp_id != self.cp_id:
            # Not for this CP - return None to skip
            return None
        
        if not encrypted:
            # Unencrypted wrapper - return payload directly
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, str):
                return json.loads(payload)
            return payload
        
        # Message is encrypted - try to decrypt
        if not self._encryption_key:
            self._set_encryption_error(
                "key_not_found",
                f"Cannot decrypt: No encryption key loaded for CP {self.cp_id}"
            )
            return None
        
        try:
            decrypted_json = CPEncryptionService.decrypt_payload(payload, self._encryption_key)
            decrypted = json.loads(decrypted_json)
            
            # Clear any previous error (recovery)
            if self._encryption_error:
                logger.info(
                    f"CP {self.cp_id}: Encryption recovered - key is now correct"
                )
                self._clear_encryption_error()
            
            return decrypted
        
        except ValueError as e:
            # Decryption failed - likely key mismatch
            self._set_encryption_error(
                "key_mismatch",
                f"Decryption failed for CP {self.cp_id}: Key mismatch. "
                f"Central and CP encryption keys do not match. "
                f"Error: {str(e)}"
            )
            return None
        
        except Exception as e:
            self._set_encryption_error(
                "decryption_failed",
                f"Unexpected decryption error: {str(e)}"
            )
            return None
    
    def _set_encryption_error(self, error_type: str, message: str):
        """Record an encryption error for display."""
        self._encryption_error = message
        self._encryption_error_type = error_type
        logger.error(f"CP {self.cp_id} ENCRYPTION ERROR: {message}")
        
        # Also include in status updates so Central and front-end can see it
        # The next status update will include this error
    
    def _clear_encryption_error(self):
        """Clear encryption error (recovery)."""
        self._encryption_error = None
        self._encryption_error_type = None
    
    def get_encryption_status(self) -> dict:
        """Get encryption status for health check/display."""
        return {
            "enabled": self._encryption_enabled,
            "key_loaded": self._encryption_key is not None,
            "error": self._encryption_error,
            "error_type": self._encryption_error_type
        }


async def main():
    """Main entry point for CP Engine service."""
    parser = argparse.ArgumentParser(description="EV CP Engine")
    parser.add_argument("--kafka-bootstrap", type=str, help="Kafka bootstrap servers")
    parser.add_argument("--cp-id", type=str, help="Charging Point ID")
    parser.add_argument("--health-port", type=int, help="TCP health check port")
    parser.add_argument("--log-level", type=str, help="Log level")
    
    args = parser.parse_args()
    
    # Build config from args (only non-None values), env vars will fill the rest
    config_dict = {k: v for k, v in vars(args).items() if v is not None and k != 'log_level'}
    config = CPEngineConfig(**config_dict)
    
    # Use log level from args or config
    log_level = args.log_level if args.log_level else config.log_level
    
    # Configure logging  
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>CP_E:{extra[cp_id]}</cyan> | <level>{message}</level>",
        level=log_level
    )
    logger.configure(extra={"cp_id": config.cp_id})
    
    # Initialize engine
    engine = CPEngine(config)
    
    try:
        await engine.start()
        
        # Process messages
        await engine.process_messages()
    
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
