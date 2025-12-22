#!/usr/bin/env python3
"""
Quick test script for EV_W Weather module.
Tests configuration loading and basic functionality.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evcharging.apps.ev_weather.config import WeatherConfig
from evcharging.apps.ev_weather.location_manager import LocationManager


def test_config():
    """Test configuration loading."""
    print("\n" + "="*60)
    print("Testing Configuration Loading")
    print("="*60)
    
    config = WeatherConfig()
    
    # Try loading
    if config.load():
        print("✅ Configuration loaded successfully")
    else:
        print("❌ Configuration loading failed")
        return False
    
    # Validate
    if config.validate():
        print("✅ Configuration validated")
    else:
        print("❌ Configuration validation failed")
        return False
    
    # Display config
    print("\nConfiguration Details:")
    print(f"  API Key: {'*' * (len(config.api_key) - 4) + config.api_key[-4:]}")
    print(f"  Base URL: {config.base_url}")
    print(f"  Polling Interval: {config.polling_interval}s")
    print(f"  Temperature Unit: {config.temperature_unit}")
    
    return True


def test_location_manager():
    """Test location manager functionality."""
    print("\n" + "="*60)
    print("Testing Location Manager")
    print("="*60)
    
    manager = LocationManager()
    
    # Test adding locations
    print("\n📍 Adding locations...")
    manager.add_location("Istanbul")
    manager.add_location("London")
    manager.add_location("Tokyo")
    
    # Test listing
    locations = manager.get_locations()
    print(f"✅ Current locations ({len(locations)}): {', '.join(locations)}")
    
    # Test removing
    print("\n➖ Removing 'London'...")
    manager.remove_location("London")
    print(f"✅ Remaining: {', '.join(manager.get_locations())}")
    
    # Test thread safety (concurrent access)
    print("\n🔒 Testing thread safety...")
    import threading
    
    def add_cities():
        for i in range(5):
            manager.add_location(f"City-{i}")
    
    threads = [threading.Thread(target=add_cities) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    print(f"✅ Thread-safe operations completed")
    print(f"   Total locations: {manager.count()}")
    
    # Test file operations
    print("\n💾 Testing file save/load...")
    manager.save_to_file("test_locations.txt")
    
    new_manager = LocationManager()
    new_manager.load_from_file("test_locations.txt")
    print(f"✅ Loaded {new_manager.count()} locations from file")
    
    # Cleanup
    os.remove("test_locations.txt")
    
    return True


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("  🧪 EV_W Module Test Suite")
    print("="*60)
    
    tests = [
        ("Configuration", test_config),
        ("Location Manager", test_location_manager),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n❌ Test '{name}' failed with exception: {e}")
            failed += 1
    
    # Summary
    print("\n" + "="*60)
    print("  Test Summary")
    print("="*60)
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print("="*60)
    
    if failed == 0:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please check configuration.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
