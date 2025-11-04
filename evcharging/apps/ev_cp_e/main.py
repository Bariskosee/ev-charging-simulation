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
from datetime import datetime
from loguru import logger

from evcharging.common.config import CPEngineConfig, TOPICS
from evcharging.common.kafka import KafkaProducerHelper, KafkaConsumerHelper, ensure_topics
from evcharging.common.messages import (
    CentralCommand, CPStatus, CPTelemetry, CommandType
)
from evcharging.common.states import CPState, CPEvent, transition, StateTransitionError
from evcharging.common.utils import utc_now


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
    
    async def start(self):
        """Initialize and start the CP Engine."""
        logger.info(f"Starting CP Engine: {self.cp_id}")
        
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
        
        # Start health check TCP server
        await self.start_health_server()
        
        # Auto-activate CP for immediate availability
        await self.change_state(CPEvent.CONNECT, "Engine started - auto-connecting")
        
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
            
            # Send status update to Central
            status = CPStatus(
                cp_id=self.cp_id,
                state=self.state.value,
                reason=reason or f"Event: {event}"
            )
            await self.producer.send(TOPICS["CP_STATUS"], status, key=self.cp_id)
        
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
        
        # Transition back to ACTIVATED
        await self.change_state(CPEvent.STOP_SUPPLY, reason)
        self.current_session = None
    
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
                
                # Emit telemetry
                telemetry = CPTelemetry(
                    cp_id=self.cp_id,
                    kw=self.config.kw_rate,
                    kwh=self.current_session.cumulative_kwh,
                    euros=self.current_session.cumulative_euros,
                    driver_id=self.current_session.driver_id,
                    session_id=self.current_session.session_id
                )
                await self.producer.send(TOPICS["CP_TELEMETRY"], telemetry, key=self.cp_id)
                
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
                    
                    # Respond with OK if engine is running
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
                        command = CentralCommand(**value)
                        await self.handle_command(command)
                        
                        # Break loop if shutdown was commanded
                        if not self._running:
                            break
                
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        except Exception as e:
            if self._running:  # Only log if not intentionally stopped
                logger.error(f"Error in message processing loop: {e}")


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
