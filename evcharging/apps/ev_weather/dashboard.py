"""
Weather Dashboard - FastAPI web interface.
Provides view of current weather data for all monitored locations.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import TYPE_CHECKING, Dict, Any
from loguru import logger

if TYPE_CHECKING:
    from evcharging.apps.ev_weather.main import EVWeatherController


def create_weather_dashboard(controller: "EVWeatherController") -> FastAPI:
    """Create FastAPI application for weather dashboard."""
    
    app = FastAPI(title="EV Weather Dashboard", version="0.1.0")
    
    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        """Main dashboard page."""
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>EV Weather Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            font-size: 14px;
        }
        .weather-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .weather-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .weather-card:hover {
            transform: translateY(-5px);
        }
        .city-name {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        .temperature {
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        .description {
            font-size: 18px;
            color: #666;
            text-transform: capitalize;
            margin-bottom: 15px;
        }
        .details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }
        .detail-item {
            font-size: 14px;
            color: #666;
        }
        .detail-label {
            font-weight: 600;
            color: #333;
        }
        .timestamp {
            font-size: 12px;
            color: #999;
            text-align: center;
            margin-top: 10px;
        }
        .no-data {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
            color: #666;
        }
        .locations-info {
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .locations-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        .location-tag {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 14px;
        }
        .refresh-info {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌤️ EV Weather Dashboard</h1>
            <div class="subtitle">Real-time weather monitoring for charging station locations</div>
        </div>
        
        <div class="locations-info">
            <strong>Monitored Locations:</strong>
            <div class="locations-list" id="locations-list">
                <div style="color: #999;">Loading...</div>
            </div>
        </div>
        
        <div class="weather-grid" id="weather-grid">
            <div class="no-data">Loading weather data...</div>
        </div>
        
        <div class="refresh-info">
            Auto-refreshing every 30 seconds
        </div>
    </div>

    <script>
        async function loadWeather() {
            try {
                const response = await fetch('/weather');
                const data = await response.json();
                
                const grid = document.getElementById('weather-grid');
                const locationsList = document.getElementById('locations-list');
                
                // Update locations list
                if (data.locations && data.locations.length > 0) {
                    locationsList.innerHTML = data.locations
                        .map(loc => `<div class="location-tag">${loc}</div>`)
                        .join('');
                } else {
                    locationsList.innerHTML = '<div style="color: #999;">No locations configured</div>';
                }
                
                // Update weather cards
                if (data.weather && Object.keys(data.weather).length > 0) {
                    grid.innerHTML = Object.entries(data.weather).map(([city, weather]) => `
                        <div class="weather-card">
                            <div class="city-name">${city}</div>
                            <div class="temperature">${weather.temperature.toFixed(1)}°C</div>
                            <div class="description">${weather.description}</div>
                            <div class="details">
                                ${weather.feels_like ? `
                                <div class="detail-item">
                                    <span class="detail-label">Feels like:</span><br>
                                    ${weather.feels_like.toFixed(1)}°C
                                </div>
                                ` : ''}
                                ${weather.humidity ? `
                                <div class="detail-item">
                                    <span class="detail-label">Humidity:</span><br>
                                    ${weather.humidity}%
                                </div>
                                ` : ''}
                                ${weather.wind_speed ? `
                                <div class="detail-item">
                                    <span class="detail-label">Wind:</span><br>
                                    ${weather.wind_speed.toFixed(1)} m/s
                                </div>
                                ` : ''}
                            </div>
                            <div class="timestamp">Updated: ${weather.timestamp}</div>
                        </div>
                    `).join('');
                } else {
                    grid.innerHTML = '<div class="no-data">No weather data available yet. Weather service is polling...</div>';
                }
            } catch (error) {
                console.error('Failed to load weather:', error);
                document.getElementById('weather-grid').innerHTML = 
                    '<div class="no-data">Failed to load weather data</div>';
            }
        }
        
        // Load immediately and then every 30 seconds
        loadWeather();
        setInterval(loadWeather, 30000);
    </script>
</body>
</html>
        """
        return HTMLResponse(content=html_content)
    
    @app.get("/weather")
    async def get_weather():
        """Get current weather data for all monitored locations."""
        try:
            locations = controller.location_manager.get_locations()
            weather_data = {}
            
            if controller.weather_service:
                for city in locations:
                    data = controller.weather_service.get_weather_data(city)
                    if data:
                        weather_data[city] = {
                            "temperature": data.temperature,
                            "description": data.description,
                            "timestamp": data.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            "feels_like": data.feels_like,
                            "humidity": data.humidity,
                            "wind_speed": data.wind_speed
                        }
            
            return {
                "locations": locations,
                "weather": weather_data,
                "total_locations": len(locations),
                "total_with_data": len(weather_data)
            }
        except Exception as e:
            logger.error(f"Error getting weather data: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )
    
    @app.get("/api/locations")
    async def list_locations():
        """Get list of currently monitored locations."""
        try:
            locations = controller.location_manager.get_locations()
            return {
                "locations": locations,
                "count": len(locations)
            }
        except Exception as e:
            logger.error(f"Error listing locations: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )
    
    @app.post("/api/locations/{city}")
    async def add_location(city: str):
        """Add a new location to monitor (allows runtime changes without interactive menu)."""
        try:
            if controller.location_manager.add_location(city):
                return {
                    "success": True,
                    "message": f"Location '{city}' added successfully",
                    "locations": controller.location_manager.get_locations()
                }
            else:
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "message": f"Location '{city}' already exists or is invalid"
                    }
                )
        except Exception as e:
            logger.error(f"Error adding location: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )
    
    @app.delete("/api/locations/{city}")
    async def remove_location(city: str):
        """Remove a location from monitoring (allows runtime changes without interactive menu)."""
        try:
            if controller.location_manager.remove_location(city):
                return {
                    "success": True,
                    "message": f"Location '{city}' removed successfully",
                    "locations": controller.location_manager.get_locations()
                }
            else:
                return JSONResponse(
                    status_code=404,
                    content={
                        "success": False,
                        "message": f"Location '{city}' not found"
                    }
                )
        except Exception as e:
            logger.error(f"Error removing location: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )
    
    return app
