#!/bin/bash
# Quick start script for EV_W Weather module

echo "=============================================="
echo "  🌤️  EV_W Weather Control Office"
echo "=============================================="
echo ""

# Check if API key is configured
if grep -q "your_api_key_here" .env 2>/dev/null; then
    echo "⚠️  WARNING: OpenWeather API key not configured!"
    echo ""
    echo "Please follow these steps:"
    echo ""
    echo "1. Get a free API key from:"
    echo "   https://openweathermap.org/api"
    echo ""
    echo "2. Edit .env file and replace 'your_api_key_here' with your actual key:"
    echo "   OPENWEATHER_API_KEY=your_actual_key_here"
    echo ""
    echo "3. Run this script again"
    echo ""
    exit 1
fi

echo "✅ Configuration found"
echo ""
echo "Starting EV_W Weather module..."
echo ""

# Run the weather module
python -m evcharging.apps.ev_weather.main
