# EV_W Weather Module - Quick Start Guide

## 🚀 Quick Start (5 minutes)

### Step 1: Get Your API Key

1. Visit [OpenWeather API](https://openweathermap.org/api)
2. Click "Sign Up" and create a free account
3. Navigate to "API keys" section in your dashboard
4. Copy your API key (32-character hexadecimal string)

### Step 2: Configure the API Key

**Option A: Using .env file (Recommended)**

Edit the `.env` file in your project root:

```bash
# Find this line:
OPENWEATHER_API_KEY=your_api_key_here

# Replace with your actual key:
OPENWEATHER_API_KEY=YOUR_ACTUAL_API_KEY_HERE
```

**Option B: Using environment variable**

```bash
export OPENWEATHER_API_KEY=YOUR_ACTUAL_API_KEY_HERE
```

### Step 3: Run the Module

```bash
# Using the quick start script
./run_weather.sh

# Or directly with Python
python -m evcharging.apps.ev_weather.main
```

### Step 4: Use the Interactive Menu

Once running, you'll see:

```
============================================================
  🌤️  EV_W - Weather Control Office
  Real-time Weather Monitoring for EV Charging Stations
============================================================

------------------------------------------------------------
  📋 MENU OPTIONS
------------------------------------------------------------
  1. ➕ Add new city/location
  2. ➖ Remove city/location
  3. 📍 List monitored locations
  4. 📂 Load locations from file
  5. 💾 Save locations to file
  6. 🗑️  Clear all locations
  0. 🚪 Shutdown EV_W service
------------------------------------------------------------

👉 Enter choice:
```

## 📖 Common Operations

### Add a City

1. Press `1`
2. Enter city name: `Madrid`
3. Watch the logs - next API call includes Madrid!

### Remove a City

1. Press `2`
2. Enter city name or number from list
3. Confirm removal

### Load Multiple Cities from File

1. Create/edit `locations.txt`:
   ```
   Madrid
   Barcelona
   Paris
   London
   ```
2. Press `4`
3. Enter filename (or press Enter for default)

### View Current Weather

Watch the logs for real-time updates:

```
2025-12-22 14:30:15 | INFO | EV_W | 🌡️  Istanbul: 15.5°C - clear sky (Updated: 14:30:15)
2025-12-22 14:30:15 | INFO | EV_W | 🌡️  Madrid: 18.2°C - partly cloudy (Updated: 14:30:15)
```

## 🧪 Testing

Run the test suite to verify configuration:

```bash
python test_ev_weather.py
```

Expected output:

```
============================================================
  🧪 EV_W Module Test Suite
============================================================

Testing Configuration Loading
✅ Configuration loaded successfully
✅ Configuration validated

Testing Location Manager
✅ Current locations (3): Istanbul, London, Tokyo
✅ Thread-safe operations completed

============================================================
  Test Summary
============================================================
  ✅ Passed: 2
  ❌ Failed: 0
============================================================

🎉 All tests passed!
```

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   User (Console)                     │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │   WeatherMenu        │ (Thread 1)
         │  - Add/Remove cities │
         │  - Interactive UI    │
         └──────────┬───────────┘
                    │ Thread-Safe
                    ▼
         ┌──────────────────────┐
         │  LocationManager     │ (Shared State)
         │  - RLock protection  │
         │  - City list         │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  WeatherService      │ (AsyncIO Loop)
         │  - Poll API every 4s │
         │  - Concurrent fetches│
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  OpenWeather API     │
         └──────────────────────┘
```

## 🔧 Configuration Files

### .env (Primary)

```env
OPENWEATHER_API_KEY=your_key_here
WEATHER_POLLING_INTERVAL=4
WEATHER_TEMPERATURE_UNIT=metric
```

### config.json (Alternative)

```json
{
  "weather": {
    "api_key": "your_key_here",
    "polling_interval": 4,
    "temperature_unit": "metric"
  }
}
```

### locations.txt (Cities List)

```text
# One city per line
Istanbul
Ankara
Madrid
```

## 💡 Tips & Best Practices

### Performance

- Free tier: 60 API calls/minute
- With 3 cities + 4s interval = 45 calls/minute ✅
- With 20 cities + 4s interval = 300 calls/minute ⚠️ (upgrade needed)

### City Names

- Use English names: "Istanbul" not "İstanbul"
- Country codes for disambiguation: "Portland,US" vs "Portland,UK"
- Check spelling - "Lndon" will fail

### Thread Safety

All operations are thread-safe:
- Menu runs in separate thread
- Weather polling runs in AsyncIO loop
- LocationManager uses RLock for synchronization

## 🐛 Troubleshooting

### "API key missing" error

**Solution**: Edit `.env` file and set `OPENWEATHER_API_KEY`

### "401 Unauthorized" error

**Solution**: 
- Check API key is correct
- Wait 10-15 minutes after creating new key (activation time)

### "404 Not Found" for city

**Solution**:
- Check city name spelling
- Try with country code: "Paris,FR"
- Use the city finder: https://openweathermap.org/find

### No weather data appearing

**Solution**:
- Check internet connection
- Verify API key is active
- Check logs for error messages
- Ensure cities are added (option 3 to list)

### Menu not responding

**Solution**:
- Press Enter to refresh
- Use Ctrl+C then option 0 to shutdown
- Check terminal supports interactive input

## 🔗 Integration with EV Charging

### Use Case 1: Temperature-Based Rate Adjustment

```python
from evcharging.apps.ev_weather.weather_service import WeatherService

temp = weather_service.get_temperature("Istanbul")
if temp and temp < 0:
    # Reduce charging rate in cold weather
    charging_rate = base_rate * 0.8
```

### Use Case 2: Weather Alerts

```python
weather_data = weather_service.get_weather_data("Istanbul")
if weather_data and "storm" in weather_data.description.lower():
    send_alert("Weather warning: Potential charging disruption")
```

### Use Case 3: Historical Logging

Log weather conditions with each charging session for analysis.

## 📚 Additional Resources

- [OpenWeather API Docs](https://openweathermap.org/api)
- [Python AsyncIO Guide](https://docs.python.org/3/library/asyncio.html)
- [Threading in Python](https://docs.python.org/3/library/threading.html)

## 🆘 Support

For issues or questions:
1. Check this guide
2. Review logs for error messages
3. Run test suite: `python test_ev_weather.py`
4. Check API key validity on OpenWeather dashboard

---

**Happy Weather Monitoring! 🌤️**
