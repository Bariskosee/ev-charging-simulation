# EV_W Module - Live Demo Script

## 🎬 Demo Scenario: Add City at Runtime

This demonstrates the core feature: **adding a city while the service is running, and seeing it immediately included in the next API call.**

### Before You Start

1. Get your OpenWeather API key from https://openweathermap.org/api
2. Edit `.env` file:
   ```
   OPENWEATHER_API_KEY=your_actual_key_here
   ```

### Step-by-Step Demo

#### 1. Start the Service

```bash
./run_weather.sh
```

**Expected Output:**
```
============================================================
  🌤️  EV_W - Weather Control Office
  Real-time Weather Monitoring for EV Charging Stations
============================================================

2025-12-22 14:00:00 | INFO | EV_W | ✅ Configuration validated successfully
2025-12-22 14:00:00 | INFO | EV_W |    API Key: **************************a1b2
2025-12-22 14:00:00 | INFO | EV_W | 🌤️  Weather service started
2025-12-22 14:00:01 | INFO | EV_W | Weather menu started

------------------------------------------------------------
  📋 MENU OPTIONS
------------------------------------------------------------
  1. ➕ Add new city/location
  2. ➖ Remove city/location
  3. 📍 List monitored locations
  ...

�� Enter choice:
```

#### 2. Check Initial Locations

**Input:** `3` (List locations)

**Expected Output:**
```
📍 Currently Monitored Locations
----------------------------------------
Total: 3 location(s)

  1. Ankara
  2. Istanbul
  3. Izmir
```

#### 3. Watch Initial Weather Data

**You'll see in logs (every 4 seconds):**
```
2025-12-22 14:00:04 | INFO | EV_W | 🌡️  Ankara: 12.3°C - clear sky (Updated: 14:00:04)
2025-12-22 14:00:04 | INFO | EV_W | 🌡️  Istanbul: 15.5°C - partly cloudy (Updated: 14:00:04)
2025-12-22 14:00:04 | INFO | EV_W | 🌡️  Izmir: 18.1°C - clear sky (Updated: 14:00:04)
```

#### 4. Add a New City (The Magic Moment! ✨)

**At exactly 14:00:05, user inputs:**

**Input:** `1` (Add new city)  
**Input:** `Madrid`

**Expected Output:**
```
➕ Add New Location
----------------------------------------
Enter city name: Madrid
✅ Added 'Madrid' to monitoring
   Next API call will include this location

👉 Enter choice:
```

**Log Output:**
```
2025-12-22 14:00:05 | INFO | EV_W | ✅ Added location: Madrid
```

#### 5. Observe Immediate Adaptation

**Next API call at 14:00:08 (3 seconds later!):**

```
2025-12-22 14:00:08 | INFO | EV_W | 🌡️  Ankara: 12.4°C - clear sky (Updated: 14:00:08)
2025-12-22 14:00:08 | INFO | EV_W | 🌡️  Istanbul: 15.6°C - partly cloudy (Updated: 14:00:08)
2025-12-22 14:00:08 | INFO | EV_W | 🌡️  Izmir: 18.2°C - clear sky (Updated: 14:00:08)
2025-12-22 14:00:08 | INFO | EV_W | 🌡️  Madrid: 20.1°C - sunny (Updated: 14:00:08) ← NEW!
```

**✅ SUCCESS:** Madrid was added at 14:00:05, and appears in the very next API call at 14:00:08!

**No restart required. No configuration file edit. Pure runtime dynamism!**

#### 6. Remove a City

**Input:** `2` (Remove city)  
**Input:** `Ankara`

**Expected Output:**
```
➖ Remove Location
----------------------------------------
Current locations:
  1. Ankara
  2. Istanbul
  3. Izmir
  4. Madrid

Enter city name or number to remove: Ankara
✅ Removed 'Ankara' from monitoring

👉 Enter choice:
```

#### 7. Verify Removal

**Next API call at 14:00:12:**

```
2025-12-22 14:00:12 | INFO | EV_W | 🌡️  Istanbul: 15.5°C - partly cloudy (Updated: 14:00:12)
2025-12-22 14:00:12 | INFO | EV_W | 🌡️  Izmir: 18.1°C - clear sky (Updated: 14:00:12)
2025-12-22 14:00:12 | INFO | EV_W | 🌡️  Madrid: 20.2°C - sunny (Updated: 14:00:12)
```

**Note:** Ankara is gone! Only 3 cities remain.

#### 8. Save Configuration

**Input:** `5` (Save to file)  
**Input:** (press Enter for default filename)

**Expected Output:**
```
💾 Save Locations to File
----------------------------------------
Enter filename (default: locations.txt):
✅ Saved 3 location(s) to locations.txt
```

**File content (`locations.txt`):**
```
# EV_W Monitored Locations
# One city per line

Istanbul
Izmir
Madrid
```

#### 9. Graceful Shutdown

**Input:** `0` (Shutdown)  
**Input:** `yes`

**Expected Output:**
```
🚪 Shutting Down EV_W Service
----------------------------------------
⚠️  Are you sure? (yes/no): yes
✅ Shutdown initiated...

2025-12-22 14:01:00 | INFO | EV_W | Shutting down EV_W services...
2025-12-22 14:01:00 | INFO | EV_W | Weather service stopped
2025-12-22 14:01:00 | INFO | EV_W | Saved 3 locations to locations.txt
2025-12-22 14:01:00 | INFO | EV_W | ✅ EV_W shutdown complete
```

## 🎯 Key Observations

### Runtime Adaptation
- **Add city at T=5s** → **Appears at T=8s** (next cycle)
- **Remove city at T=10s** → **Gone at T=12s** (next cycle)
- **No restarts, no file edits** ← This is the magic!

### Thread Safety
```
Timeline:
T=5.0s: Menu thread adds "Madrid"
T=5.0s: LocationManager acquires lock
T=5.0s: LocationManager adds "Madrid" to set
T=5.0s: LocationManager releases lock

T=8.0s: Weather service thread gets locations
T=8.0s: LocationManager acquires lock
T=8.0s: LocationManager returns copy [Istanbul, Izmir, Madrid]
T=8.0s: LocationManager releases lock
T=8.0s: Weather service fetches all 3 cities concurrently

No race conditions! ✅
```

### Configuration Persistence
- Changes saved to `locations.txt` on shutdown
- Next startup loads saved configuration
- Survives crashes (save manually with option 5)

## 🧪 Testing the Module

Run the automated test suite:

```bash
python test_ev_weather.py
```

**Expected Output:**
```
============================================================
  🧪 EV_W Module Test Suite
============================================================

Testing Configuration Loading
============================================================
✅ Configuration loaded successfully
✅ Configuration validated

Configuration Details:
  API Key: ****************************a1b2
  Base URL: https://api.openweathermap.org/data/2.5/weather
  Polling Interval: 4s
  Temperature Unit: metric

Testing Location Manager
============================================================

📍 Adding locations...
✅ Current locations (3): Istanbul, London, Tokyo

➖ Removing 'London'...
✅ Remaining: Istanbul, Tokyo

🔒 Testing thread safety...
✅ Thread-safe operations completed
   Total locations: 17

💾 Testing file save/load...
✅ Loaded 17 locations from file

============================================================
  Test Summary
============================================================
  ✅ Passed: 2
  ❌ Failed: 0
============================================================

🎉 All tests passed!
```

## 🐛 Common Issues During Demo

### Issue 1: "API key missing"
**Solution:** Edit `.env` file and set `OPENWEATHER_API_KEY=your_key`

### Issue 2: "401 Unauthorized"
**Solution:** Wait 10-15 minutes after creating API key (activation time)

### Issue 3: No weather data appears
**Solution:** 
- Check internet connection
- Try option 3 to verify cities are added
- Check for typos in city names

### Issue 4: City not found (404)
**Solution:** 
- Use English names: "Istanbul" not "İstanbul"
- Add country code: "Portland,US" not just "Portland"
- Check spelling carefully

## 🎓 Learning Points

1. **No Hardcoding:** API key loaded from external file
2. **Runtime Flexibility:** Add/remove cities without restart
3. **Thread Safety:** Menu and polling run concurrently safely
4. **Modularity:** Easy to swap configuration sources
5. **AsyncIO Power:** Multiple cities fetched concurrently

## 📚 Next Steps

After the demo, try:

1. **Integration Example:**
   ```bash
   python examples/weather_integration.py
   ```

2. **Batch Load Cities:**
   - Edit `locations.txt`
   - Run service
   - Use option 4 to load file

3. **Modify Polling Interval:**
   - Edit `.env`: `WEATHER_POLLING_INTERVAL=10`
   - Restart service
   - Observe slower updates

4. **Temperature Units:**
   - Edit `.env`: `WEATHER_TEMPERATURE_UNIT=imperial`
   - See Fahrenheit instead of Celsius

---

**Demo Complete! 🎉**

You've seen:
- ✅ External configuration loading
- ✅ Dynamic location management at runtime
- ✅ Thread-safe concurrent operations
- ✅ Modular, extensible design
- ✅ Real-time adaptation to changes

**The EV_W module is ready for production! 🚀**
