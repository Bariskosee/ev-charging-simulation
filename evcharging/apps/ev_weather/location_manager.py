"""
Dynamic location manager for EV_W module.
Provides thread-safe management of monitored cities/locations.
"""

import threading
from typing import List, Set
from loguru import logger


class LocationManager:
    """
    Thread-safe manager for monitored locations.
    Allows dynamic addition/removal of cities during runtime.
    """
    
    def __init__(self, initial_locations: List[str] = None):
        """
        Initialize location manager.
        
        Args:
            initial_locations: Optional list of initial cities to monitor
        """
        self._lock = threading.RLock()
        self._locations: Set[str] = set(initial_locations or [])
        logger.info(f"LocationManager initialized with {len(self._locations)} locations")
    
    def add_location(self, city: str) -> bool:
        """
        Add a new city to monitor.
        
        Args:
            city: City name to add
            
        Returns:
            bool: True if added, False if already exists
        """
        with self._lock:
            city = city.strip()
            if not city:
                return False
            
            if city in self._locations:
                logger.warning(f"Location '{city}' already being monitored")
                return False
            
            self._locations.add(city)
            logger.info(f"✅ Added location: {city}")
            return True
    
    def remove_location(self, city: str) -> bool:
        """
        Remove a city from monitoring.
        
        Args:
            city: City name to remove
            
        Returns:
            bool: True if removed, False if not found
        """
        with self._lock:
            city = city.strip()
            if city not in self._locations:
                logger.warning(f"Location '{city}' not found")
                return False
            
            self._locations.remove(city)
            logger.info(f"❌ Removed location: {city}")
            return True
    
    def get_locations(self) -> List[str]:
        """
        Get current list of monitored locations.
        Returns a copy to prevent external modification.
        
        Returns:
            List[str]: Copy of current locations
        """
        with self._lock:
            return sorted(list(self._locations))
    
    def clear_locations(self) -> int:
        """
        Clear all monitored locations.
        
        Returns:
            int: Number of locations cleared
        """
        with self._lock:
            count = len(self._locations)
            self._locations.clear()
            logger.info(f"Cleared all {count} locations")
            return count
    
    def has_locations(self) -> bool:
        """Check if any locations are being monitored."""
        with self._lock:
            return len(self._locations) > 0
    
    def count(self) -> int:
        """Get count of monitored locations."""
        with self._lock:
            return len(self._locations)
    
    def load_from_file(self, filepath: str) -> int:
        """
        Load locations from a text file (one per line).
        
        Args:
            filepath: Path to file containing city names
            
        Returns:
            int: Number of locations loaded
        """
        with self._lock:
            try:
                with open(filepath, 'r') as f:
                    count = 0
                    for line in f:
                        city = line.strip()
                        if city and not city.startswith('#'):
                            self._locations.add(city)
                            count += 1
                    logger.info(f"Loaded {count} locations from {filepath}")
                    return count
            except FileNotFoundError:
                logger.warning(f"Locations file not found: {filepath}")
                return 0
            except Exception as e:
                logger.error(f"Error loading locations from file: {e}")
                return 0
    
    def save_to_file(self, filepath: str) -> bool:
        """
        Save current locations to a text file.
        
        Args:
            filepath: Path to save locations
            
        Returns:
            bool: True if saved successfully
        """
        with self._lock:
            try:
                with open(filepath, 'w') as f:
                    f.write("# EV_W Monitored Locations\n")
                    f.write("# One city per line\n\n")
                    for city in sorted(self._locations):
                        f.write(f"{city}\n")
                logger.info(f"Saved {len(self._locations)} locations to {filepath}")
                return True
            except Exception as e:
                logger.error(f"Error saving locations to file: {e}")
                return False
