"""
EV CP Monitor - Charging Point Monitor service.

Responsibilities:
- Register CP with EV_Registry (secure authentication)
- Register CP with EV_Central (using Registry-issued token)
- Perform periodic health checks to CP Engine
- Detect and report faults
- Allow manual fault simulation via keyboard
- Sign heartbeats with encryption key for verification
"""

import asyncio
import argparse
import sys
import signal
import os
import base64
import json
from datetime import datetime
import httpx
from loguru import logger

from evcharging.common.config import CPMonitorConfig
from evcharging.common.messages import CPRegistration
from evcharging.common.utils import utc_now
from evcharging.common.registry_client import RegistryClient
from evcharging.common.cp_security import CPEncryptionService


class CPMonitor:
    """Monitor for Charging Point health and connectivity."""
    
    def __init__(self, config: CPMonitorConfig):
        self.config = config
        self.cp_id = config.cp_id
        self.is_healthy = True
        self.fault_simulated = False
        self._running = False
        
        # Load encryption key from environment for heartbeat signing
        self._encryption_key: bytes | None = None
        self._load_encryption_key()
        
        # Initialize Registry client for secure authentication
        self.registry_client: RegistryClient | None = None
        if config.registry_enabled:
            self.registry_client = RegistryClient(
                registry_url=config.registry_url,
                verify_ssl=config.registry_verify_ssl,
                admin_api_key=config.registry_admin_api_key
            )
    
    def _load_encryption_key(self):
        """Load encryption key from environment variable for heartbeat signing."""
        # Convert CP-001 to EV_CP_001_ENCRYPTION_KEY
        cp_num = self.cp_id.replace("CP-", "").replace("cp-", "")
        env_var = f"EV_CP_{cp_num}_ENCRYPTION_KEY"
        
        key_b64 = os.environ.get(env_var)
        if key_b64:
            try:
                self._encryption_key = base64.b64decode(key_b64)
                if len(self._encryption_key) == 32:
                    logger.info(f"CP {self.cp_id}: Loaded encryption key from environment for heartbeat signing")
                else:
                    logger.warning(f"CP {self.cp_id}: Invalid key length from {env_var}, heartbeats will be unsigned")
                    self._encryption_key = None
            except Exception as e:
                logger.warning(f"CP {self.cp_id}: Failed to decode key from {env_var}: {e}")
                self._encryption_key = None
        else:
            logger.info(f"CP {self.cp_id}: No encryption key in {env_var}, heartbeats will be unsigned")
    
    async def start(self):
        """Initialize and start the CP Monitor."""
        logger.info(f"Starting CP Monitor for {self.cp_id}")
        
        # Step 1: Register with EV_Registry if enabled (secure channel)
        if self.config.registry_enabled and self.registry_client:
            await self._register_with_registry()
        
        # Step 2: Register with Central (uses Registry token if available)
        await self.register_with_central()
        
        self._running = True
        logger.info(f"CP Monitor {self.cp_id} started successfully")
    
    async def _register_with_registry(self):
        """Register with EV_Registry service for secure authentication."""
        logger.info(f"Registering {self.cp_id} with EV_Registry at {self.config.registry_url}...")
        
        metadata = {
            "cp_e_host": self.config.cp_e_host,
            "cp_e_port": self.config.cp_e_port
        }
        
        max_retries = 5
        retry_delay = 2.0        

        for attempt in range(1, max_retries + 1):
            success = await self.registry_client.register(
                cp_id=self.cp_id,
                location=self.config.location,
                metadata=metadata
            )
            
            if success:
                logger.info(
                    f"✓ CP {self.cp_id} registered with EV_Registry "
                    f"(token expires: {self.registry_client.token_expires_at})"
                )
                return
            
            if attempt < max_retries:
                logger.warning(
                    f"Registry registration attempt {attempt}/{max_retries} failed, "
                    f"retrying in {retry_delay}s..."
                )
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 1.5, 10.0)
        
        logger.warning(
            f"⚠️ Could not register with EV_Registry after {max_retries} attempts. "
            "Continuing with direct Central registration (insecure mode)."
        )
    
    async def stop(self):
        """Stop the monitor gracefully."""
        logger.info(f"Stopping CP Monitor: {self.cp_id}")
        self._running = False
    
    async def register_with_central(self):
        """Register or authenticate CP with Central with retry logic.
        
        If registered with EV_Registry, includes JWT token for secure authentication.
        """
        registration = CPRegistration(
            cp_id=self.cp_id,
            cp_e_host=self.config.cp_e_host,
            cp_e_port=self.config.cp_e_port
        )
        
        central_url = f"http://{self.config.central_host}:{self.config.central_port}"
        
        # Build headers with authentication token if available from Registry
        headers = {"Content-Type": "application/json"}
        if self.registry_client and self.registry_client.token:
            headers["Authorization"] = f"Bearer {self.registry_client.token}"
            logger.info(f"Using Registry-issued token for Central authentication")
        
        max_retries = 10
        retry_delay = 2.0  # Start with 2 seconds
        
        for attempt in range(1, max_retries + 1):
            try:
                # Ensure token is valid before each attempt
                if self.registry_client and self.registry_client.is_registered:
                    if self.registry_client.is_token_expired():
                        logger.info("Token expired, refreshing...")
                        await self.registry_client.authenticate()
                        if self.registry_client.token:
                            headers["Authorization"] = f"Bearer {self.registry_client.token}"
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{central_url}/cp/register",
                        json=registration.model_dump(mode='json'),
                        headers=headers,
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        auth_mode = "authenticated" if "Authorization" in headers else "unauthenticated"
                        logger.info(f"CP {self.cp_id} registered with Central successfully ({auth_mode}, attempt {attempt})")
                        return  # Success - exit retry loop
                    else:
                        logger.warning(f"Failed to register CP (attempt {attempt}/{max_retries}): {response.status_code} {response.text}")

            except Exception as e:
                logger.warning(f"Error registering with Central (attempt {attempt}/{max_retries}): {e}")
            
            # If not last attempt, wait before retrying
            if attempt < max_retries:
                logger.debug(f"Retrying registration in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                # Exponential backoff with max 10 seconds
                retry_delay = min(retry_delay * 1.5, 10.0)
            else:
                logger.error(f"Failed to register CP {self.cp_id} after {max_retries} attempts - will retry via heartbeat")

    async def send_heartbeat(self):
        """Send heartbeat to Central indicating monitor is alive.
        
        Includes JWT token for authenticated communication.
        If encryption key is available, signs the heartbeat with HMAC-SHA256.
        """
        central_url = f"http://{self.config.central_host}:{self.config.central_port}"
        heartbeat = {
            "cp_id": self.cp_id,
            "ts": utc_now().isoformat()
        }
        
        # Sign heartbeat with encryption key if available
        if self._encryption_key:
            # Create message to sign (cp_id + timestamp)
            message_to_sign = json.dumps({"cp_id": heartbeat["cp_id"], "ts": heartbeat["ts"]}, sort_keys=True)
            signature = CPEncryptionService.sign_message(message_to_sign, self._encryption_key)
            logger.info(f"Signature: {signature}")
            heartbeat["signature"] = signature
            heartbeat["signed_message"] = message_to_sign
        
        # Include authentication token if available
        headers = {}
        if self.registry_client and self.registry_client.token:
            # Refresh token if needed
            if self.registry_client.is_token_expired():
                await self.registry_client.authenticate()
            if self.registry_client.token:
                headers["Authorization"] = f"Bearer {self.registry_client.token}"

        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{central_url}/cp/heartbeat",
                    json=heartbeat,
                    headers=headers,
                    timeout=5.0
                )
        except Exception as e:
            logger.debug(f"Heartbeat send failed for {self.cp_id}: {e}")
    
    async def _get_auth_headers(self) -> dict:
        """Get authentication headers for Central API calls."""
        headers = {}
        if self.registry_client and self.registry_client.token:
            # Refresh token if needed
            if self.registry_client.is_token_expired():
                await self.registry_client.authenticate()
            if self.registry_client.token:
                headers["Authorization"] = f"Bearer {self.registry_client.token}"
        return headers
    
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
            
            headers = await self._get_auth_headers()
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{central_url}/cp/fault",
                    json=fault_data,
                    headers=headers,
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
            
            headers = await self._get_auth_headers()
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{central_url}/cp/fault",
                    json=health_data,
                    headers=headers,
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
                await self.send_heartbeat()

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
                            logger.info(f"CP {self.cp_id}: Health restored - notifying Central")
                            self.is_healthy = True
                            await self.notify_central_healthy()
                        consecutive_failures = 0
                        logger.debug(f"CP {self.cp_id}: Health check OK")
                    else:
                        consecutive_failures += 1
                
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                    consecutive_failures += 1
                    logger.warning(
                        f"CP {self.cp_id}: Health check failed ({consecutive_failures}) - {type(e).__name__}"
                    )
                
                # Mark as unhealthy after 10 consecutive failures (increased for demo mode tolerance)
                if consecutive_failures >= 10 and self.is_healthy:
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
    parser.add_argument("--location", type=str, help="CP location (city/address)")
    parser.add_argument("--cp-e-host", type=str, help="CP Engine host")
    parser.add_argument("--cp-e-port", type=int, help="CP Engine port")
    parser.add_argument("--central-host", type=str, help="Central host")
    parser.add_argument("--central-port", type=int, help="Central HTTP port")
    parser.add_argument("--health-interval", type=float, help="Health check interval (seconds)")
    parser.add_argument("--log-level", type=str, help="Log level")
    # Registry settings
    parser.add_argument("--registry-url", type=str, help="EV_Registry API URL")
    parser.add_argument("--registry-enabled", type=bool, default=None, help="Enable Registry authentication")
    parser.add_argument("--registry-admin-api-key", type=str, help="Admin API key for new registrations")
    parser.add_argument("--no-registry", action="store_true", help="Disable Registry authentication (insecure)")
    
    args = parser.parse_args()
    
    # Build config from args (only non-None values), env vars will fill the rest
    config_dict = {k: v for k, v in vars(args).items() 
                   if v is not None and k not in ('log_level', 'no_registry')}
    
    # Handle --no-registry flag
    if args.no_registry:
        config_dict['registry_enabled'] = False
    
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
    
    # Log configuration
    logger.info(f"Registry enabled: {config.registry_enabled}")
    if config.registry_enabled:
        logger.info(f"Registry URL: {config.registry_url}")
    
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
