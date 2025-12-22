"""
Weather service for EV_W module.
Polls OpenWeather API and provides temperature data for charging stations.
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from datetime import datetime
from loguru import logger

from .config import WeatherConfig
from .location_manager import LocationManager
from evcharging.common.error_manager import (
    ErrorManager, 
    ErrorCategory, 
    ErrorSeverity,
    ErrorSource,
    report_service_error,
    report_connection_error
)


class WeatherData:
    """Container for weather information."""
    
    def __init__(self, city: str, temperature: float, 
                 description: str, timestamp: datetime):
        self.city = city
        self.temperature = temperature
        self.description = description
        self.timestamp = timestamp
        self.feels_like: Optional[float] = None
        self.humidity: Optional[int] = None
        self.wind_speed: Optional[float] = None
    
    def __str__(self) -> str:
        return (f"{self.city}: {self.temperature}°C - {self.description} "
                f"(Updated: {self.timestamp.strftime('%H:%M:%S')})")


class WeatherService:
    """
    Service to poll weather data from OpenWeather API.
    Adapts dynamically to location changes.
    """
    
    def __init__(self, config: WeatherConfig, location_manager: LocationManager):
        """
        Initialize weather service.
        
        Args:
            config: Weather configuration
            location_manager: Location manager for dynamic cities
        """
        self.config = config
        self.location_manager = location_manager
        self.latest_data: Dict[str, WeatherData] = {}
        self._running = False
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Initialize error manager
        self.error_manager = ErrorManager()
        self._consecutive_api_failures = 0
        self._max_consecutive_failures = 3
    
    async def start(self):
        """Start the weather polling service."""
        if self._running:
            logger.warning("Weather service already running")
            return
        
        self._running = True
        self._session = aiohttp.ClientSession()
        
        logger.info("🌤️  Weather service started")
        logger.info(f"   Polling interval: {self.config.polling_interval}s")
        
        await self._polling_loop()
    
    async def stop(self):
        """Stop the weather polling service."""
        self._running = False
        if self._session:
            await self._session.close()
        logger.info("Weather service stopped")
    
    async def _polling_loop(self):
        """Main polling loop - runs continuously."""
        while self._running:
            try:
                locations = self.location_manager.get_locations()
                
                if not locations:
                    logger.debug("No locations to monitor, waiting...")
                    await asyncio.sleep(self.config.polling_interval)
                    continue
                
                # Poll all locations concurrently
                tasks = [self._fetch_weather(city) for city in locations]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Track failures for this poll cycle
                poll_failures = 0
                
                # Update latest data
                for result in results:
                    if isinstance(result, WeatherData):
                        self.latest_data[result.city] = result
                        logger.info(f"🌡️  {result}")
                    elif isinstance(result, Exception):
                        poll_failures += 1
                        logger.error(f"Weather fetch error: {result}")
                
                # Track consecutive failures for overall service health
                if poll_failures == len(results) and len(results) > 0:
                    self._consecutive_api_failures += 1
                    if self._consecutive_api_failures >= self._max_consecutive_failures:
                        # Report persistent service error
                        self.error_manager.report_error(
                            category=ErrorCategory.SERVICE,
                            source=ErrorSource.WEATHER,
                            target="OpenWeather API",
                            message="Unable to access weather data. OpenWeather connection unavailable.",
                            severity=ErrorSeverity.ERROR,
                            technical_detail=f"{poll_failures} consecutive failures"
                        )
                else:
                    # Reset counter on any success
                    if self._consecutive_api_failures >= self._max_consecutive_failures:
                        # Resolve the error if we recover
                        self.error_manager.resolve_errors_for_target(
                            target="OpenWeather API",
                            category=ErrorCategory.SERVICE,
                            resolution_message="OpenWeather API connection restored"
                        )
                    self._consecutive_api_failures = 0
                
                # Remove data for locations no longer monitored
                current_cities = set(locations)
                for city in list(self.latest_data.keys()):
                    if city not in current_cities:
                        del self.latest_data[city]
                        logger.debug(f"Removed cached data for {city}")
                
                await asyncio.sleep(self.config.polling_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Polling loop error: {e}")
                self.error_manager.report_error(
                    category=ErrorCategory.SYSTEM,
                    source=ErrorSource.WEATHER,
                    target="Weather Service",
                    message=f"Weather polling loop error: {str(e)}",
                    severity=ErrorSeverity.ERROR,
                    technical_detail=str(e)
                )
                await asyncio.sleep(self.config.polling_interval)
    
    async def _fetch_weather(self, city: str) -> WeatherData:
        """
        Fetch weather data for a specific city.
        
        Args:
            city: City name
            
        Returns:
            WeatherData: Weather information
        """
        params = {
            'q': city,
            'appid': self.config.api_key,
            'units': self.config.temperature_unit
        }
        
        try:
            async with self._session.get(self.config.base_url, params=params) as response:
                if response.status != 200:
                    error_text = await response.text()
                    error_msg = f"API error for {city}: {response.status} - {error_text}"
                    # Report specific city weather fetch error
                    self.error_manager.report_error(
                        category=ErrorCategory.SERVICE,
                        source=ErrorSource.WEATHER,
                        target=city,
                        message=f"Unable to fetch weather for {city}: HTTP {response.status}",
                        severity=ErrorSeverity.WARNING,
                        technical_detail=error_text[:100]
                    )
                    raise Exception(error_msg)
                
                data = await response.json()
                # Resolve any previous error for this city
                self.error_manager.resolve_errors_for_target(
                    target=city,
                    category=ErrorCategory.SERVICE,
                    resolution_message=f"Weather data for {city} successfully retrieved"
                )
                return self._parse_weather_data(city, data)
                
        except aiohttp.ClientConnectorError as e:
            # Network connectivity error
            self.error_manager.report_error(
                category=ErrorCategory.CONNECTION,
                source=ErrorSource.WEATHER,
                target="OpenWeather API",
                message=f"Network error accessing weather service",
                severity=ErrorSeverity.ERROR,
                technical_detail=str(e)
            )
            raise
        except aiohttp.ClientError as e:
            # General HTTP client error
            self.error_manager.report_error(
                category=ErrorCategory.CONNECTION,
                source=ErrorSource.WEATHER,
                target=city,
                message=f"HTTP client error for weather API",
                severity=ErrorSeverity.WARNING,
                technical_detail=str(e)
            )
            raise
        except Exception as e:
            logger.error(f"Failed to fetch weather for {city}: {e}")
            raise
    
    def _parse_weather_data(self, city: str, data: Dict[str, Any]) -> WeatherData:
        """Parse API response into WeatherData object."""
        main = data.get('main', {})
        weather = data.get('weather', [{}])[0]
        wind = data.get('wind', {})
        
        weather_data = WeatherData(
            city=city,
            temperature=main.get('temp', 0.0),
            description=weather.get('description', 'unknown'),
            timestamp=datetime.now()
        )
        
        weather_data.feels_like = main.get('feels_like')
        weather_data.humidity = main.get('humidity')
        weather_data.wind_speed = wind.get('speed')
        
        return weather_data
    
    def get_temperature(self, city: str) -> Optional[float]:
        """
        Get current temperature for a city.
        
        Args:
            city: City name
            
        Returns:
            Optional[float]: Temperature in configured units, or None if not available
        """
        weather_data = self.latest_data.get(city)
        return weather_data.temperature if weather_data else None
    
    def get_all_temperatures(self) -> Dict[str, float]:
        """Get temperatures for all monitored cities."""
        return {
            city: data.temperature 
            for city, data in self.latest_data.items()
        }
    
    def get_weather_data(self, city: str) -> Optional[WeatherData]:
        """Get full weather data for a city."""
        return self.latest_data.get(city)
    
    def get_errors(self) -> List[Dict[str, Any]]:
        """
        Get all current errors from the weather service.
        
        Returns:
            List of error dictionaries for display
        """
        return self.error_manager.get_errors_for_display()
    
    def get_error_summary(self) -> Dict[str, int]:
        """
        Get a summary of errors by severity.
        
        Returns:
            Dictionary with severity counts
        """
        return self.error_manager.get_error_summary()
