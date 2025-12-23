"""
Configuration loader for EV_W module.
Handles loading API keys and settings from external sources.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from loguru import logger


class WeatherConfig:
    """Configuration manager for Weather module."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration loader.
        
        Args:
            config_file: Optional path to config file. If None, uses .env
        """
        self.config_file = config_file
        self.api_key: Optional[str] = None
        self.base_url: str = "https://api.openweathermap.org/data/2.5/weather"
        self.polling_interval: int = 4  # seconds
        self.temperature_unit: str = "metric"  # celsius
        self.default_cities: List[str] = []  # Cities to monitor by default
        self.locations_file: str = "locations.txt"  # File to store/load locations
        self.dashboard_port: int = 8003  # HTTP dashboard port
        
    def load(self) -> bool:
        """
        Load configuration from external sources.
        Tries multiple sources in order: .env file, environment variables, config.json
        Also loads supplementary config (default_cities, locations_file, dashboard_port) from config.json if available.
        
        Returns:
            bool: True if configuration loaded successfully
        """
        api_key_loaded = False
        
        # Try loading from .env file
        if self._load_from_env_file():
            logger.info("Configuration loaded from .env file")
            api_key_loaded = True
        
        # Try loading from environment variables
        elif self._load_from_environment():
            logger.info("Configuration loaded from environment variables")
            api_key_loaded = True
        
        # Try loading from config.json
        elif self._load_from_json():
            logger.info("Configuration loaded from config.json")
            api_key_loaded = True
        
        # Even if API key was loaded from env, try to load supplementary config from JSON
        if api_key_loaded:
            self._load_supplementary_from_json()
        
        if not api_key_loaded:
            logger.error("Failed to load configuration from any source")
            return False
        
        return True
    
    def _load_from_env_file(self) -> bool:
        """Load configuration from .env file."""
        env_file = Path(".env")
        if not env_file.exists():
            return False
        
        try:
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        if key == 'OPENWEATHER_API_KEY':
                            self.api_key = value
                        elif key == 'WEATHER_POLLING_INTERVAL':
                            self.polling_interval = int(value)
                        elif key == 'WEATHER_TEMPERATURE_UNIT':
                            self.temperature_unit = value
            
            return self.api_key is not None
        except Exception as e:
            logger.error(f"Error reading .env file: {e}")
            return False
    
    def _load_from_environment(self) -> bool:
        """Load configuration from environment variables."""
        self.api_key = os.getenv('OPENWEATHER_API_KEY')
        
        if interval := os.getenv('WEATHER_POLLING_INTERVAL'):
            self.polling_interval = int(interval)
        
        if unit := os.getenv('WEATHER_TEMPERATURE_UNIT'):
            self.temperature_unit = unit
        
        return self.api_key is not None
    
    def _load_from_json(self) -> bool:
        """Load configuration from config.json file."""
        config_file = Path(self.config_file or "config.json")
        if not config_file.exists():
            return False
        
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
                
            weather_config = data.get('weather', {})
            self.api_key = weather_config.get('api_key')
            self.polling_interval = weather_config.get('polling_interval', 4)
            self.temperature_unit = weather_config.get('temperature_unit', 'metric')
            self.locations_file = weather_config.get('locations_file', 'locations.txt')
            self.dashboard_port = weather_config.get('dashboard_port', 8003)
            
            # Read default cities from locations section
            locations_config = data.get('locations', {})
            self.default_cities = locations_config.get('default_cities', [])
            
            return self.api_key is not None
        except Exception as e:
            logger.error(f"Error reading config.json: {e}")
            return False
    
    def _load_supplementary_from_json(self) -> None:
        """Load supplementary configuration (default_cities, etc.) from config.json even if API key came from env."""
        config_file = Path(self.config_file or "config.json")
        if not config_file.exists():
            return
        
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
                
            # Load weather-specific settings if not already set from env
            weather_config = data.get('weather', {})
            if 'locations_file' in weather_config:
                self.locations_file = weather_config.get('locations_file', 'locations.txt')
            if 'dashboard_port' in weather_config:
                self.dashboard_port = weather_config.get('dashboard_port', 8003)
            
            # Always load default cities from JSON if available
            locations_config = data.get('locations', {})
            if 'default_cities' in locations_config:
                self.default_cities = locations_config.get('default_cities', [])
                logger.info(f"Loaded {len(self.default_cities)} default cities from config.json")
        except Exception as e:
            logger.warning(f"Could not load supplementary config from config.json: {e}")
    
    def validate(self) -> bool:
        """
        Validate the configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        if not self.api_key:
            logger.error("❌ OPENWEATHER_API_KEY is missing!")
            logger.error("   Please set it in one of the following:")
            logger.error("   1. .env file: OPENWEATHER_API_KEY=your_api_key")
            logger.error("   2. Environment variable: export OPENWEATHER_API_KEY=your_api_key")
            logger.error("   3. config.json file with 'weather.api_key' field")
            return False
        
        if len(self.api_key) < 10:
            logger.error("❌ OPENWEATHER_API_KEY appears to be invalid (too short)")
            return False
        
        logger.info(f"✅ Configuration validated successfully")
        logger.info(f"   API Key: {'*' * (len(self.api_key) - 4) + self.api_key[-4:]}")
        logger.info(f"   Polling Interval: {self.polling_interval}s")
        logger.info(f"   Temperature Unit: {self.temperature_unit}")
        
        return True
    
    def get_config_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        return {
            'api_key': self.api_key,
            'base_url': self.base_url,
            'polling_interval': self.polling_interval,
            'temperature_unit': self.temperature_unit,
            'default_cities': self.default_cities,
            'locations_file': self.locations_file,
            'dashboard_port': self.dashboard_port
        }
