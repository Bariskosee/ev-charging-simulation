"""
Example integration of EV_W Weather module with EV Charging system.
Demonstrates how to use weather data in charging decisions.
"""

import asyncio
from loguru import logger

from evcharging.apps.ev_weather.config import WeatherConfig
from evcharging.apps.ev_weather.location_manager import LocationManager
from evcharging.apps.ev_weather.weather_service import WeatherService


class ChargingRateAdjuster:
    """
    Adjusts EV charging rates based on ambient temperature.
    
    Logic:
    - Below 0°C: Reduce rate by 20% (battery efficiency drops)
    - 0-10°C: Reduce rate by 10%
    - 10-30°C: Normal rate (optimal temperature)
    - Above 30°C: Reduce rate by 15% (prevent overheating)
    """
    
    def __init__(self, weather_service: WeatherService, base_rate_kw: float = 22.0):
        """
        Initialize rate adjuster.
        
        Args:
            weather_service: Weather service instance
            base_rate_kw: Base charging rate in kW
        """
        self.weather_service = weather_service
        self.base_rate_kw = base_rate_kw
    
    def get_adjusted_rate(self, location: str) -> float:
        """
        Get temperature-adjusted charging rate for a location.
        
        Args:
            location: City name
            
        Returns:
            float: Adjusted charging rate in kW
        """
        temperature = self.weather_service.get_temperature(location)
        
        if temperature is None:
            logger.warning(f"No temperature data for {location}, using base rate")
            return self.base_rate_kw
        
        # Temperature-based adjustment
        if temperature < 0:
            multiplier = 0.80  # 20% reduction
            reason = "Cold weather - reduced battery efficiency"
        elif temperature < 10:
            multiplier = 0.90  # 10% reduction
            reason = "Cool weather - slight efficiency impact"
        elif temperature <= 30:
            multiplier = 1.00  # No adjustment
            reason = "Optimal temperature range"
        else:
            multiplier = 0.85  # 15% reduction
            reason = "Hot weather - prevent overheating"
        
        adjusted_rate = self.base_rate_kw * multiplier
        
        logger.info(
            f"Charging rate for {location}: {adjusted_rate:.2f} kW "
            f"(temp: {temperature}°C, {reason})"
        )
        
        return adjusted_rate


class WeatherAlertSystem:
    """
    Monitors weather conditions and sends alerts for extreme conditions.
    """
    
    def __init__(self, weather_service: WeatherService):
        self.weather_service = weather_service
        self.alert_thresholds = {
            'cold_temp': -5,      # °C
            'hot_temp': 40,       # °C
            'keywords': ['storm', 'thunder', 'heavy rain', 'snow']
        }
    
    async def monitor_and_alert(self):
        """Continuously monitor weather and send alerts."""
        while True:
            for location, weather_data in self.weather_service.latest_data.items():
                # Temperature alerts
                if weather_data.temperature < self.alert_thresholds['cold_temp']:
                    self._send_alert(
                        location,
                        f"⚠️ COLD ALERT: {weather_data.temperature}°C - "
                        f"Consider reducing charging sessions"
                    )
                
                if weather_data.temperature > self.alert_thresholds['hot_temp']:
                    self._send_alert(
                        location,
                        f"⚠️ HEAT ALERT: {weather_data.temperature}°C - "
                        f"Monitor battery temperatures closely"
                    )
                
                # Weather condition alerts
                description = weather_data.description.lower()
                for keyword in self.alert_thresholds['keywords']:
                    if keyword in description:
                        self._send_alert(
                            location,
                            f"⚠️ WEATHER ALERT: {weather_data.description} - "
                            f"Potential service disruption"
                        )
                        break
            
            await asyncio.sleep(60)  # Check every minute
    
    def _send_alert(self, location: str, message: str):
        """Send an alert (log for demo, could integrate with notification system)."""
        logger.warning(f"[ALERT] {location}: {message}")
        # In production, could send to:
        # - Email/SMS service
        # - Slack/Teams webhook
        # - Kafka topic for alert subscribers
        # - Database for alert history


async def example_integration():
    """
    Example showing how to integrate weather module with EV charging system.
    """
    logger.info("Starting EV_W integration example...")
    
    # Initialize weather module
    config = WeatherConfig()
    if not config.load() or not config.validate():
        logger.error("Failed to initialize weather config")
        return
    
    # Setup locations (charging station cities)
    location_manager = LocationManager([
        "Istanbul",
        "Ankara",
        "Izmir",
        "Antalya"
    ])
    
    # Start weather service
    weather_service = WeatherService(config, location_manager)
    weather_task = asyncio.create_task(weather_service.start())
    
    # Wait for first data collection
    await asyncio.sleep(10)
    
    # Example 1: Adjust charging rates based on temperature
    logger.info("\n" + "="*60)
    logger.info("Example 1: Temperature-Based Rate Adjustment")
    logger.info("="*60)
    
    rate_adjuster = ChargingRateAdjuster(weather_service)
    
    for location in location_manager.get_locations():
        adjusted_rate = rate_adjuster.get_adjusted_rate(location)
        logger.info(f"  {location}: {adjusted_rate:.2f} kW")
    
    # Example 2: Get all temperatures
    logger.info("\n" + "="*60)
    logger.info("Example 2: Current Temperatures at All Stations")
    logger.info("="*60)
    
    temps = weather_service.get_all_temperatures()
    for city, temp in temps.items():
        logger.info(f"  {city}: {temp}°C")
    
    # Example 3: Weather alert monitoring
    logger.info("\n" + "="*60)
    logger.info("Example 3: Starting Weather Alert Monitor")
    logger.info("="*60)
    
    alert_system = WeatherAlertSystem(weather_service)
    alert_task = asyncio.create_task(alert_system.monitor_and_alert())
    
    # Run for demonstration
    logger.info("\nRunning for 30 seconds...")
    await asyncio.sleep(30)
    
    # Cleanup
    alert_task.cancel()
    await weather_service.stop()
    weather_task.cancel()
    
    logger.info("\n✅ Integration example completed")


if __name__ == "__main__":
    asyncio.run(example_integration())
