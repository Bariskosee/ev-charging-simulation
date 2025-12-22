"""
EV_W - Weather Control Office
Main entry point for the weather monitoring module.
"""

import asyncio
import signal
import sys
from loguru import logger

from .config import WeatherConfig
from .location_manager import LocationManager
from .weather_service import WeatherService
from .menu import WeatherMenu


class EVWeatherController:
    """Main controller for EV_W weather monitoring service."""
    
    def __init__(self):
        """Initialize the weather controller."""
        self.config = WeatherConfig()
        self.location_manager = LocationManager()
        self.weather_service = None
        self.menu = None
        self._shutdown_event = asyncio.Event()
    
    async def initialize(self) -> bool:
        """
        Initialize and validate configuration.
        
        Returns:
            bool: True if initialization successful
        """
        logger.info("Initializing EV_W Weather Control Office...")
        
        # Load configuration
        if not self.config.load():
            logger.error("Failed to load configuration")
            return False
        
        # Validate configuration
        if not self.config.validate():
            return False
        
        # Initialize services
        self.weather_service = WeatherService(self.config, self.location_manager)
        self.menu = WeatherMenu(self.location_manager, self._request_shutdown)
        
        logger.info("✅ EV_W initialized successfully")
        return True
    
    def _request_shutdown(self):
        """Request shutdown from menu."""
        self._shutdown_event.set()
    
    async def run(self):
        """Run the weather monitoring service."""
        # Load default locations if available
        self.location_manager.load_from_file("locations.txt")
        
        # If no locations loaded, add some defaults
        if not self.location_manager.has_locations():
            logger.info("No locations configured, adding defaults...")
            self.location_manager.add_location("Istanbul")
            self.location_manager.add_location("Ankara")
            self.location_manager.add_location("Izmir")
        
        # Start menu in separate thread
        self.menu.start()
        
        # Start weather service
        weather_task = asyncio.create_task(self.weather_service.start())
        
        # Wait for shutdown signal
        try:
            await self._shutdown_event.wait()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        
        # Cleanup
        await self.shutdown()
        
        # Wait for weather task to complete
        weather_task.cancel()
        try:
            await weather_task
        except asyncio.CancelledError:
            pass
    
    async def shutdown(self):
        """Shutdown all services gracefully."""
        logger.info("Shutting down EV_W services...")
        
        self.menu.stop()
        
        if self.weather_service:
            await self.weather_service.stop()
        
        # Save locations for next run
        self.location_manager.save_to_file("locations.txt")
        
        logger.info("✅ EV_W shutdown complete")


async def main():
    """Main entry point."""
    # Configure logger
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>EV_W</cyan> | <level>{message}</level>",
        level="INFO"
    )
    
    # Create and run controller
    controller = EVWeatherController()
    
    if not await controller.initialize():
        logger.error("Failed to initialize EV_W")
        logger.error("\n📝 Configuration Help:")
        logger.error("   Create a .env file with: OPENWEATHER_API_KEY=your_api_key_here")
        logger.error("   Or set environment variable: export OPENWEATHER_API_KEY=your_key")
        logger.error("   Get your API key from: https://openweathermap.org/api")
        sys.exit(1)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        controller._request_shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the service
    await controller.run()


if __name__ == "__main__":
    asyncio.run(main())
