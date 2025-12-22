"""
Interactive console menu for EV_W module.
Allows dynamic management of monitored locations at runtime.
"""

import threading
import time
from typing import Callable, Optional
from loguru import logger

from .location_manager import LocationManager


class WeatherMenu:
    """
    Interactive console menu for managing weather monitoring.
    Runs in a separate thread to allow concurrent operation.
    """
    
    def __init__(self, location_manager: LocationManager, 
                 on_shutdown: Optional[Callable] = None):
        """
        Initialize weather menu.
        
        Args:
            location_manager: LocationManager instance to control
            on_shutdown: Optional callback when shutdown requested
        """
        self.location_manager = location_manager
        self.on_shutdown = on_shutdown
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the menu in a separate thread."""
        if self._running:
            logger.warning("Menu already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_menu, daemon=True)
        self._thread.start()
        logger.info("Weather menu started")
    
    def stop(self):
        """Stop the menu thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Weather menu stopped")
    
    def _run_menu(self):
        """Main menu loop (runs in separate thread)."""
        # Give time for weather service to start
        time.sleep(1)
        
        self._display_welcome()
        
        while self._running:
            try:
                self._display_menu()
                choice = input("\n👉 Enter choice: ").strip()
                
                if choice == '1':
                    self._add_location()
                elif choice == '2':
                    self._remove_location()
                elif choice == '3':
                    self._list_locations()
                elif choice == '4':
                    self._load_from_file()
                elif choice == '5':
                    self._save_to_file()
                elif choice == '6':
                    self._clear_locations()
                elif choice == '0':
                    self._shutdown()
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                
                time.sleep(0.1)  # Brief pause
                
            except KeyboardInterrupt:
                print("\n\n⚠️  Ctrl+C detected. Use option 0 to shutdown gracefully.")
                time.sleep(1)
            except Exception as e:
                logger.error(f"Menu error: {e}")
                time.sleep(1)
    
    def _display_welcome(self):
        """Display welcome message."""
        print("\n" + "="*60)
        print("  🌤️  EV_W - Weather Control Office")
        print("  Real-time Weather Monitoring for EV Charging Stations")
        print("="*60)
        print()
    
    def _display_menu(self):
        """Display menu options."""
        print("\n" + "-"*60)
        print("  📋 MENU OPTIONS")
        print("-"*60)
        print("  1. ➕ Add new city/location")
        print("  2. ➖ Remove city/location")
        print("  3. 📍 List monitored locations")
        print("  4. 📂 Load locations from file")
        print("  5. 💾 Save locations to file")
        print("  6. 🗑️  Clear all locations")
        print("  0. 🚪 Shutdown EV_W service")
        print("-"*60)
    
    def _add_location(self):
        """Add a new location."""
        print("\n➕ Add New Location")
        print("-"*40)
        city = input("Enter city name: ").strip()
        
        if not city:
            print("❌ City name cannot be empty")
            return
        
        if self.location_manager.add_location(city):
            print(f"✅ Added '{city}' to monitoring")
            print(f"   Next API call will include this location")
        else:
            print(f"⚠️  '{city}' is already being monitored")
    
    def _remove_location(self):
        """Remove a location."""
        print("\n➖ Remove Location")
        print("-"*40)
        
        locations = self.location_manager.get_locations()
        if not locations:
            print("⚠️  No locations currently monitored")
            return
        
        print("Current locations:")
        for i, city in enumerate(locations, 1):
            print(f"  {i}. {city}")
        
        choice = input("\nEnter city name or number to remove: ").strip()
        
        # Check if it's a number
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(locations):
                city = locations[idx]
            else:
                print("❌ Invalid number")
                return
        else:
            city = choice
        
        if self.location_manager.remove_location(city):
            print(f"✅ Removed '{city}' from monitoring")
        else:
            print(f"❌ Location '{city}' not found")
    
    def _list_locations(self):
        """List all monitored locations."""
        print("\n📍 Currently Monitored Locations")
        print("-"*40)
        
        locations = self.location_manager.get_locations()
        if not locations:
            print("⚠️  No locations currently monitored")
            print("   Use option 1 to add locations")
            return
        
        print(f"Total: {len(locations)} location(s)\n")
        for i, city in enumerate(locations, 1):
            print(f"  {i}. {city}")
    
    def _load_from_file(self):
        """Load locations from a file."""
        print("\n📂 Load Locations from File")
        print("-"*40)
        filename = input("Enter filename (default: locations.txt): ").strip()
        
        if not filename:
            filename = "locations.txt"
        
        count = self.location_manager.load_from_file(filename)
        if count > 0:
            print(f"✅ Loaded {count} location(s) from {filename}")
        else:
            print(f"⚠️  No locations loaded from {filename}")
    
    def _save_to_file(self):
        """Save locations to a file."""
        print("\n💾 Save Locations to File")
        print("-"*40)
        filename = input("Enter filename (default: locations.txt): ").strip()
        
        if not filename:
            filename = "locations.txt"
        
        if self.location_manager.save_to_file(filename):
            print(f"✅ Saved {self.location_manager.count()} location(s) to {filename}")
        else:
            print(f"❌ Failed to save locations")
    
    def _clear_locations(self):
        """Clear all locations."""
        print("\n🗑️  Clear All Locations")
        print("-"*40)
        
        count = self.location_manager.count()
        if count == 0:
            print("⚠️  No locations to clear")
            return
        
        confirm = input(f"⚠️  Remove all {count} location(s)? (yes/no): ").strip().lower()
        
        if confirm in ['yes', 'y']:
            cleared = self.location_manager.clear_locations()
            print(f"✅ Cleared {cleared} location(s)")
        else:
            print("❌ Cancelled")
    
    def _shutdown(self):
        """Shutdown the service."""
        print("\n🚪 Shutting Down EV_W Service")
        print("-"*40)
        confirm = input("⚠️  Are you sure? (yes/no): ").strip().lower()
        
        if confirm in ['yes', 'y']:
            print("✅ Shutdown initiated...")
            self._running = False
            if self.on_shutdown:
                self.on_shutdown()
        else:
            print("❌ Shutdown cancelled")
