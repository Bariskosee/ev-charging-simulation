"""
EV CP Monitor - Charging Point Monitor service.

Responsibilities:
- Register CP with Central on startup
- Perform periodic health checks to CP Engine
- Detect and report faults
- Allow manual fault simulation via keyboard
"""

import asyncio
import argparse
import sys
import signal
from datetime import datetime
import httpx
from loguru import logger

from evcharging.common.config import CPMonitorConfig
from evcharging.common.messages import CPRegistration
from evcharging.common.utils import utc_now
from evcharging.common.utils import utc_now


class CPMonitor:
    """Monitor for Charging Point health and connectivity."""
    
    def __init__(self, config: CPMonitorConfig):
        self.config = config
        self.cp_id = config.cp_id
        self.is_healthy = True
        self.fault_simulated = False
        self._running = False
    
    async def start(self):
        """Initialize and start the CP Monitor."""
        logger.info(f"Starting CP Monitor for {self.cp_id}")
        
        # Register with Central
        await self.register_with_central()
        
        self._running = True
        logger.info(f"CP Monitor {self.cp_id} started successfully")
    
    async def stop(self):
        """Stop the monitor gracefully."""
        logger.info(f"Stopping CP Monitor: {self.cp_id}")
        self._running = False
    
    async def register_with_central(self):
        """Register or authenticate CP with Central."""
        registration = CPRegistration(
            cp_id=self.cp_id,
            cp_e_host=self.config.cp_e_host,
            cp_e_port=self.config.cp_e_port
        )
        
        central_url = f"http://{self.config.central_host}:{self.config.central_port}"
        max_retries = 5
        base_delay = 1
        
        for attempt in range(1, max_retries+1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{central_url}/cp/register",
                        json=registration.model_dump(mode='json'),
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        logger.info(f"CP {self.cp_id} registered with Central successfully")
                        return
                    else:
                        logger.error(f"Failed to register CP: {response.status_code} {response.text}\
                                     for the {attempt} time")
            
            except Exception as e:
                logger.error(f"Error registering with Central: {e}")

            delay = min(base_delay * (2 ** (attempt - 1)), 60)
            logger.info(f"Retrying registration in {delay:.1f}s...")
            await asyncio.sleep(delay)

    async def notify_central_fault(self):
        """Notify Central that this CP has a fault."""
        try:
            central_url = f"http://{self.config.central_host}:{self.config.central_port}"
            fault_data = {
                "cp_id": self.cp_id,
                "status": "FAULT",
                "reason": "Health check failures exceeded threshold",
                "ts": utc_now().isoformat()
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{central_url}/cp/fault",
                    json=fault_data,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    logger.info(f"CP {self.cp_id}: Fault notification sent to Central")
                else:
                    logger.error(f"Failed to notify Central of fault: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error notifying Central of fault: {e}")
    
    async def notify_central_healthy(self):
        """Notify Central that this CP health is restored."""
        try:
            central_url = f"http://{self.config.central_host}:{self.config.central_port}"
            health_data = {
                "cp_id": self.cp_id,
                "status": "HEALTHY",
                "reason": "Health check restored",
                "ts": utc_now().isoformat()
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{central_url}/cp/fault",
                    json=health_data,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    logger.info(f"CP {self.cp_id}: Health restoration notification sent to Central")
                else:
                    logger.error(f"Failed to notify Central of health restoration: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error notifying Central of health restoration: {e}")
    
    async def health_check_loop(self):
        """Periodically check CP Engine health via TCP."""
        logger.info(f"Starting health check loop for CP_E at {self.config.cp_e_host}:{self.config.cp_e_port}")
        
        consecutive_failures = 0
        
        while self._running:
            try:
                # Skip health check if fault is manually simulated
                if self.fault_simulated:
                    if self.is_healthy:
                        logger.warning(f"CP {self.cp_id}: FAULT SIMULATED - notifying Central")
                        self.is_healthy = False
                        # In production, would send fault notification to Central
                    await asyncio.sleep(self.config.health_interval)
                    continue
                
                # Attempt TCP connection to CP Engine health endpoint
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.config.cp_e_host, self.config.cp_e_port),
                        timeout=2.0
                    )
                    
                    # Send ping
                    writer.write(b"PING\n")
                    await writer.drain()
                    
                    # Read response
                    response = await asyncio.wait_for(reader.read(100), timeout=1.0)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    if response.startswith(b"OK"):
                        if not self.is_healthy:
                            logger.info(f"CP {self.cp_id}: Health restored")
                            self.is_healthy = True
                        consecutive_failures = 0
                        logger.debug(f"CP {self.cp_id}: Health check OK")
                    else:
                        consecutive_failures += 1
                
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                    consecutive_failures += 1
                    logger.warning(
                        f"CP {self.cp_id}: Health check failed ({consecutive_failures}) - {type(e).__name__}"
                    )
                
                # Mark as unhealthy after 3 consecutive failures
                if consecutive_failures >= 3 and self.is_healthy:
                    logger.error(f"CP {self.cp_id}: FAULT DETECTED - marking as unhealthy")
                    self.is_healthy = False
                    await self.notify_central_fault()
                
                # Notify when health is restored after being unhealthy
                elif consecutive_failures == 0 and not self.is_healthy:
                    logger.info(f"CP {self.cp_id}: Health restored - notifying Central")
                    self.is_healthy = True
                    await self.notify_central_healthy()
            
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
            
            await asyncio.sleep(self.config.health_interval)
    
    async def keyboard_handler(self):
        """Handle keyboard input for fault simulation."""
        logger.info("Keyboard handler ready. Press 'f' to simulate fault, 'r' to recover, 'q' to quit")
        
        # Note: This is a simplified version. In production, use aioconsole or similar
        loop = asyncio.get_event_loop()
        
        def handle_signal(sig):
            if sig == signal.SIGUSR1:
                self.fault_simulated = not self.fault_simulated
                state = "FAULT" if self.fault_simulated else "RECOVERED"
                logger.info(f"CP {self.cp_id}: Manual fault simulation {state}")
        
        # For demonstration, we'll just run without keyboard input
        # In a real deployment, you'd use aioconsole or a web interface
        while self._running:
            await asyncio.sleep(1)


async def main():
    """Main entry point for CP Monitor service."""
    parser = argparse.ArgumentParser(description="EV CP Monitor")
    parser.add_argument("--cp-id", type=str, help="Charging Point ID")
    parser.add_argument("--cp-e-host", type=str, help="CP Engine host")
    parser.add_argument("--cp-e-port", type=int, help="CP Engine port")
    parser.add_argument("--central-host", type=str, help="Central host")
    parser.add_argument("--central-port", type=int, help="Central HTTP port")
    parser.add_argument("--health-interval", type=float, help="Health check interval (seconds)")
    parser.add_argument("--log-level", type=str, help="Log level")
    
    args = parser.parse_args()
    
    # Build config from args (only non-None values), env vars will fill the rest
    config_dict = {k: v for k, v in vars(args).items() if v is not None and k != 'log_level'}
    config = CPMonitorConfig(**config_dict)
    
    # Use log level from args or config
    log_level = args.log_level if args.log_level else config.log_level
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <yellow>CP_M:{extra[cp_id]}</yellow> | <level>{message}</level>",
        level=log_level
    )
    logger.configure(extra={"cp_id": config.cp_id})
    
    # Initialize monitor
    monitor = CPMonitor(config)
    
    try:
        await monitor.start()
        
        # Run health check loop
        health_task = asyncio.create_task(monitor.health_check_loop())
        keyboard_task = asyncio.create_task(monitor.keyboard_handler())
        
        await asyncio.gather(health_task, keyboard_task)
    
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        await monitor.stop()


if __name__ == "__main__":
    asyncio.run(main())
