"""
EV Weather (EV_W) - Weather simulation service.

Responsibilities:
- Load cities from file
- Periodically generate weather data
- Detect alerts
- Notify EV Central via HTTP API
"""

import asyncio
import argparse
import sys
from dataclasses import dataclass
from typing import Dict
from loguru import logger
import random
import httpx

from datetime import datetime
from evcharging.common.config import WeatherConfig

@dataclass
class WeatherState:
    """Data class to store information about a given city and its weather state"""
    city: str
    temperature: float
    alert: bool = False
    last_update: datetime | None = None

class EVWeatherController:
    def __init__(self, config: WeatherConfig):
        self.config = config
        self.city_file = config.city_file
        self.weather_by_city: Dict[str, WeatherState] = {}
        self._running = False

    def load_cities(self):
        """Load cities from a file"""
        logger.info(f"Loading cities from {self.city_file}")

        with open(self.city_file, "r") as f:
            for line in f:
                city = line.strip(",")[1]
                if not city:
                    continue

                self.weather_by_city[city] = WeatherState(city=city, temperature=0.0)

        logger.info(f"Loaded cities: {list(self.weather_by_city.keys())}")

    async def fetch_weather(self, city: str) -> WeatherState:
        url = "https://api.openweathermap.org/data/2.5/weather"

        params = {
            "q": city,
            "appid": self.config.openweather_api_key,
            "units": "metric",
        }

        async with httpx.AsyncClient(timeout=4) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

        temperature = data["main"]["temp"]

        alert = temperature < 0 or temperature > 40

        return WeatherState(
            city=city,
            temperature=temperature,
            alert=alert,
            last_update=datetime.utcnow(),
        )

    
    async def post(self, endpoint: str, payload: dict):
        """General method using asynchronous httpx client to send data to the Central"""
        url = f"{self.config.central_http_url}{endpoint}"
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    
    async def send_weather_report(self, state: WeatherState):
        """Send the general weather report invoking the self.post method"""
        payload = {
            "city": state.city,
            "temperature": state.temperature,
            "alert": state.alert,
        }

        await self.post("/weather/report", payload)
        logger.info(f"Weather report sent for {state.city}")

    async def send_alert(self, state: WeatherState):
        """Send the weather alert invoking the self.post method"""
        payload = {
            "city": state.city,
            "temperature": state.temperature,
            "alert": True,
        }

        await self.post("/weather/alert", payload)
        logger.warning(f"ALERT sent for {state.city}")

    async def send_cancel_alert(self, state: WeatherState):
        """Send the alert cancellation invoking the self.post method"""
        payload = {
            "city": state.city,
            "temperature": state.temperature,
            "alert": False,
        }

        await self.post("/weather/cancel_alert", payload)
        logger.info(f"Alert cancelled for {state.city}")
    
    async def run(self):
        """Main loop of the weather service"""
        self._running = True

        while self._running:
            for city, previous in self.weather_by_city.items():
                try:
                    current = await self.fetch_weather(city)

                    await self.send_weather_report(current)

                    if previous:
                        if current.alert and not previous.alert:
                            await self.send_alert(current)
                        elif not current.alert and previous.alert:
                            await self.send_cancel_alert(current)

                    self.weather_by_city[city] = current

                except Exception as e:
                    logger.error(f"Weather update failed for {city}: {e}")

            await asyncio.sleep(self.config.poll_interval)

async def main():
    parser = argparse.ArgumentParser(description="EV Weather Service")
    parser.add_argument("--openweather-api", help="API to access OpenWeather")
    parser.add_argument("--central-url", help="EV Central base URL")
    parser.add_argument("--interval", type=int, help="Update interval (seconds)")
    parser.add_argument("--cities-file", help="Path to cities file")
    parser.add_argument("--log-level", default="INFO")

    args = parser.parse_args()

    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>EV_W</cyan> | <level>{message}</level>",
        level=args.log_level
    )

    config_dict = {k: v for k, v in vars(args).items() if v is not None}
    config = WeatherConfig(**config_dict)

    controller = EVWeatherController(config)

    controller.load_cities()
    await controller.run()


if __name__ == "__main__":
    asyncio.run(main())

