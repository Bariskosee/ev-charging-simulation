# EV_W - Weather Control Office

Weather monitoring module for the EV Charging distributed system (Release 2).

## Features

- ✅ **External Configuration**: API keys loaded from `.env` file (no hardcoding)
- ✅ **Dynamic Location Management**: Add/remove cities at runtime via interactive menu
- ✅ **Thread-Safe**: Concurrent menu and weather polling with proper synchronization
- ✅ **Modular Design**: Easy to extend and configure
- ✅ **Real-time Updates**: Weather polling adapts immediately to location changes
- ✅ **Persistent Storage**: Locations saved/loaded from file
- ✅ **Web Dashboard**: Real-time weather visualization at http://localhost:8003

## Configuration

### Option 1: .env File (Recommended)

Create a `.env` file in the project root:

```env
# OpenWeather API Configuration
OPENWEATHER_API_KEY=your_api_key_here

# Optional: Polling interval in seconds (default: 4)
WEATHER_POLLING_INTERVAL=4

# Optional: Temperature unit (metric/imperial/standard)
WEATHER_TEMPERATURE_UNIT=metric
```

### Option 2: Environment Variables

```bash
export OPENWEATHER_API_KEY=your_api_key_here
export WEATHER_POLLING_INTERVAL=4
export WEATHER_TEMPERATURE_UNIT=metric
```

### Option 3: config.json File

Create a `config.json` file:

```json
{
  "weather": {
    "api_key": "your_api_key_here",
    "polling_interval": 4,
    "temperature_unit": "metric"
  }
}
```

## Getting an API Key

1. Visit: https://openweathermap.org/api
2. Sign up for a free account
3. Navigate to API keys section
4. Copy your API key
5. Add it to your `.env` file

## Usage

### Running the Service

```bash
# From project root
python -m evcharging.apps.ev_weather.main
```

### Accessing the Dashboard

Once the service is running, open your browser and navigate to:

**🌐 http://localhost:8003**

The dashboard shows:
- All monitored locations
- Current temperature for each city
- Weather description (sunny, cloudy, etc.)
- Additional details: feels like, humidity, wind speed
- Last update timestamp
- Auto-refreshes every 30 seconds

### Interactive Menu

You can also use the console menu to manage locations:

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
```

### Example Workflow

1. **Start the service** - Default locations (Istanbul, Ankara, Izmir) are loaded
2. **Add a new city** - Select option 1, enter "Madrid"
3. **Watch the logs** - Next API call (within 4 seconds) will include Madrid
4. **Remove a city** - Select option 2, choose location to remove
5. **Save configuration** - Select option 5 to persist locations

## Location File Format

Create a `locations.txt` file with one city per line:

```text
# EV_W Monitored Locations
# One city per line

Istanbul
Ankara
Izmir
Madrid
Barcelona
```

## Architecture

### Thread Safety

- **LocationManager**: Uses `threading.RLock()` for safe concurrent access
- **Menu Thread**: Runs independently for user input
- **Weather Service**: AsyncIO-based polling that reads locations safely

### Components

1. **config.py**: Configuration loading and validation
2. **location_manager.py**: Thread-safe location management
3. **weather_service.py**: AsyncIO weather polling
4. **menu.py**: Interactive console interface
5. **main.py**: Main controller and entry point

### Data Flow

```
User Input (Menu Thread)
    ↓
LocationManager (Thread-Safe)
    ↓
Weather Service (AsyncIO)
    ↓
OpenWeather API
    ↓
Weather Data Storage
```

## API Response Example

```json
{
  "weather": [{"description": "clear sky"}],
  "main": {
    "temp": 15.5,
    "feels_like": 14.2,
    "humidity": 65
  },
  "wind": {"speed": 3.5}
}
```

## Error Handling

- **Missing API Key**: Application alerts user with helpful message
- **Invalid Location**: Logged as error, other locations continue
- **API Errors**: Logged and retried on next cycle
- **Network Issues**: Graceful degradation with error logging

## Extending the Module

### Adding New Configuration Sources

Edit `config.py` and add a new `_load_from_*` method:

```python
def _load_from_database(self) -> bool:
    """Load configuration from database."""
    # Your implementation
    pass
```

### Adding New Menu Options

Edit `menu.py` and add to `_display_menu()` and `_run_menu()`:

```python
elif choice == '7':
    self._your_new_feature()
```

### Integration with EV Charging System

The weather data can be used to:
- Adjust charging rates based on temperature
- Send alerts for extreme weather
- Log weather conditions with charging sessions
- Optimize charging schedules

Example integration:

```python
from evcharging.apps.ev_weather.weather_service import WeatherService

# Get temperature for a charging station location
temp = weather_service.get_temperature("Istanbul")
if temp and temp < 0:
    logger.warning(f"Low temperature alert: {temp}°C")
```

## Dependencies

- `aiohttp`: Async HTTP client for API calls
- `loguru`: Enhanced logging
- Standard library: `threading`, `asyncio`, `json`

## Troubleshooting

### API Key Issues
- Ensure key is correctly formatted (32 characters)
- Check if key is active on OpenWeather dashboard
- Verify no extra spaces/quotes in configuration

### No Weather Data
- Check internet connectivity
- Verify city names are correct (try "London" not "Lndon")
- Check API rate limits (60 calls/minute for free tier)

### Menu Not Responding
- Use Ctrl+C then option 0 to shutdown gracefully
- Check terminal supports interactive input

## Production Deployment

For production use:

1. **Use environment variables** (not .env file in version control)
2. **Implement rate limiting** for API calls
3. **Add caching** for frequently accessed locations
4. **Enable TLS/SSL** for API calls
5. **Monitor API quota** usage
6. **Add health checks** for service monitoring

## License

Part of the EV Charging Simulation System - MIT License
