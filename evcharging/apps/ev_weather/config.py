"""
Configuration loader for EV_W module.
Handles loading API keys and settings from external sources.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
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
        
    def load(self) -> bool:
        """
        Load configuration from external sources.
        Tries multiple sources in order: .env file, environment variables, config.json
        
        Returns:
            bool: True if configuration loaded successfully
        """
        # Try loading from .env file
        if self._load_from_env_file():
            logger.info("Configuration loaded from .env file")
            return True
        
        # Try loading from environment variables
        if self._load_from_environment():
            logger.info("Configuration loaded from environment variables")
            return True
        
        # Try loading from config.json
        if self._load_from_json():
            logger.info("Configuration loaded from config.json")
            return True
        
        logger.error("Failed to load configuration from any source")
        return False
    
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
            
            return self.api_key is not None
        except Exception as e:
            logger.error(f"Error reading config.json: {e}")
            return False
    
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
            'temperature_unit': self.temperature_unit
        }
