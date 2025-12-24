"""Driver dashboard FastAPI app bound to an ``EVDriver`` instance."""

from datetime import datetime
from typing import List, Literal, Optional, TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from loguru import logger

if TYPE_CHECKING:  # pragma: no cover
    from evcharging.apps.ev_driver.main import EVDriver


class Location(BaseModel):
    address: str
    city: str
    latitude: float
    longitude: float
    distance_km: Optional[float] = Field(default=None, description="Distance from driver in km")


class ChargingPointStatus(BaseModel):
    cp_id: str
    name: str
    status: Literal["FREE", "OCCUPIED", "OFFLINE"]
    power_kw: float
    connector_type: str
    location: Location
    queue_length: int = Field(default=0, ge=0)
    estimated_wait_minutes: int = Field(default=0, ge=0)
    favorite: bool = False


class ChargingPointDetail(ChargingPointStatus):
    amenities: List[str] = Field(default_factory=list)
    price_eur_per_kwh: float = 0.0
    last_updated: datetime


class SessionSummary(BaseModel):
    session_id: str
    request_id: str
    cp_id: str
    status: Literal[
        "PENDING",
        "APPROVED",
        "CHARGING",
        "COMPLETED",
        "DENIED",
        "FAILED",
        "STOPPED",
        "CANCELLED",
    ]
    queue_position: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    energy_kwh: Optional[float] = None
    cost_eur: Optional[float] = None


class SessionHistoryEntry(SessionSummary):
    receipt_url: Optional[str] = None


class RequestPayload(BaseModel):
    cp_id: str
    vehicle_id: str
    preferred_start: Optional[datetime] = None


class FavoritePayload(BaseModel):
    cp_id: str


class Notification(BaseModel):
    notification_id: str
    created_at: datetime
    message: str
    type: Literal["SESSION", "QUEUE", "ALERT"]
    read: bool = False


class BroadcastAlert(BaseModel):
    alert_id: str
    title: str
    message: str
    severity: Literal["INFO", "WARN", "CRITICAL"]
    effective_at: datetime
    expires_at: Optional[datetime] = None


def create_driver_dashboard_app(driver: "EVDriver") -> FastAPI:
    """Bind the REST API to a running ``EVDriver`` instance."""

    app = FastAPI(
        title="Driver Dashboard API",
        version="1.0.0",
        description="Driver self-service endpoints for live session management.",
    )

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "driver-dashboard"}

    @app.get("/sync-status")
    async def sync_status():
        """Get Central dashboard synchronization status.
        
        Returns:
            - central_connected: Whether Central's HTTP API is reachable
            - last_sync: Timestamp of last successful sync
            - is_stale: True if data may be outdated
            - kafka_operational: True (Kafka is separate from HTTP)
            - charging_operations_affected: False (only display affected)
        
        Note: Even if Central dashboard is down, charging requests/updates
        continue via Kafka. Only the CP status display is affected.
        """
        return driver.get_sync_status()

    # ------------------------------------------------------------------
    # Charging point discovery
    # ------------------------------------------------------------------

    @app.get("/charging-points", response_model=List[ChargingPointDetail])
    async def list_charging_points(
        city: Optional[str] = Query(None, description="Filter by city"),
        connector_type: Optional[str] = Query(None, description="Filter by connector type"),
        min_power_kw: Optional[float] = Query(None, ge=0, description="Filter by minimum power"),
        only_available: bool = Query(False, description="Return only FREE points"),
    ):
        points = await driver.dashboard_charging_points(
            city=city,
            connector_type=connector_type,
            min_power_kw=min_power_kw,
            only_available=only_available,
        )
        return points

    @app.get("/charging-points/{cp_id}", response_model=ChargingPointDetail)
    async def get_charging_point(cp_id: str):
        try:
            return await driver.dashboard_charging_point(cp_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Charging point not found")

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    @app.post("/drivers/{driver_id}/requests", response_model=SessionSummary, status_code=202)
    async def request_session(driver_id: str, payload: RequestPayload):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        driver_request = await driver.send_request(payload.cp_id)
        summary = await driver.dashboard_request_summary(driver_request.request_id)
        return summary

    @app.delete("/drivers/{driver_id}/requests/{request_id}", status_code=204)
    async def cancel_request(driver_id: str, request_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        cancelled = await driver.dashboard_cancel_request(request_id)
        if not cancelled:
            raise HTTPException(status_code=404, detail="Request not found or already active")

    @app.get("/drivers/{driver_id}/sessions/current", response_model=Optional[SessionSummary])
    async def current_session(driver_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        return await driver.dashboard_current_session()

    @app.post("/drivers/{driver_id}/sessions/{session_id}/stop", response_model=SessionSummary)
    async def stop_session(driver_id: str, session_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        summary = await driver.dashboard_stop_session(session_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Session not found")
        return summary

    @app.get("/drivers/{driver_id}/sessions/history", response_model=List[SessionHistoryEntry])
    async def session_history(driver_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        return await driver.dashboard_session_history()

    # ------------------------------------------------------------------
    # Favorites & personalization
    # ------------------------------------------------------------------

    @app.get("/drivers/{driver_id}/favorites", response_model=List[ChargingPointStatus])
    async def list_favorites(driver_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        return await driver.dashboard_favorites()

    @app.post("/drivers/{driver_id}/favorites", status_code=204)
    async def add_favorite(driver_id: str, payload: FavoritePayload):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        await driver.dashboard_add_favorite(payload.cp_id)

    @app.delete("/drivers/{driver_id}/favorites/{cp_id}", status_code=204)
    async def remove_favorite(driver_id: str, cp_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        await driver.dashboard_remove_favorite(cp_id)

    # ------------------------------------------------------------------
    # Notifications and alerts
    # ------------------------------------------------------------------

    @app.get("/drivers/{driver_id}/notifications", response_model=List[Notification])
    async def list_notifications(driver_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        return await driver.dashboard_notifications()

    @app.get("/drivers/{driver_id}/alerts", response_model=List[BroadcastAlert])
    async def list_alerts(driver_id: str):
        if driver_id != driver.driver_id:
            raise HTTPException(status_code=404, detail="Driver not found")
        return await driver.dashboard_alerts()

    @app.get("/errors")
    async def get_errors():
        """Get system errors for dashboard display."""
        return driver.get_errors()

    @app.get("/weather")
    async def get_weather():
        """Get weather data from central service for all CP locations.
        
        Returns weather data if available, or gracefully degrades with empty data
        if the central service is unreachable or returns errors.
        This endpoint NEVER crashes - it always returns a valid JSON response.
        """
        import asyncio
        import os
        import aiohttp
        
        service_status = "ok"
        
        try:
            central_url = os.getenv('DRIVER_CENTRAL_HTTP_URL', 'http://ev-central:8000')
            async with aiohttp.ClientSession() as session:
                timeout = aiohttp.ClientTimeout(total=3)
                async with session.get(f'{central_url}/weather', timeout=timeout) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            # Ensure we have valid data structure
                            return {
                                "cities": data.get("cities", []),
                                "weather": data.get("weather", {}),
                                "service_status": data.get("service_status", "ok")
                            }
                        except (ValueError, KeyError) as json_error:
                            logger.warning(f"Central service returned invalid JSON: {json_error}")
                            service_status = "degraded"
                    else:
                        logger.warning(f"Central service returned status {response.status} for weather")
                        service_status = "degraded"
        except asyncio.TimeoutError:
            logger.debug("Central weather request timed out")
            service_status = "timeout"
        except aiohttp.ClientError as e:
            logger.debug(f"Central service connection failed: {e}")
            service_status = "unavailable"
        except Exception as e:
            logger.warning(f"Error fetching weather from central: {e}")
            service_status = "error"
        
        # Always return success with empty weather data (graceful degradation)
        return {"cities": [], "weather": {}, "service_status": service_status}

    # ------------------------------------------------------------------
    # HTML Dashboard
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def driver_dashboard_home(request: Request):
        """Interactive HTML dashboard for drivers."""
        driver_id = driver.driver_id
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>🚗 Driver Dashboard - {driver_id}</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1600px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 12px;
                    padding: 30px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                }}
                
                h1 {{
                    color: #667eea;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 15px;
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .driver-badge {{
                    background: #764ba2;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 0.9em;
                }}
                
                .status-bar {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    border-left: 4px solid #667eea;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .last-update {{
                    font-size: 0.9em;
                    color: #999;
                }}
                
                .active-session {{
                    background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
                    padding: 25px;
                    border-radius: 12px;
                    border-left: 6px solid #2196f3;
                    margin-bottom: 25px;
                    box-shadow: 0 4px 12px rgba(33, 150, 243, 0.2);
                }}
                
                .active-session h3 {{
                    color: #1976d2;
                    margin-bottom: 15px;
                    font-size: 1.3em;
                }}
                
                .session-info {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                    gap: 15px;
                    margin-bottom: 15px;
                }}
                
                .info-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                
                .info-label {{
                    color: #666;
                    font-size: 0.85em;
                    margin-bottom: 5px;
                    text-transform: uppercase;
                    font-weight: 600;
                }}
                
                .info-value {{
                    color: #333;
                    font-size: 1.4em;
                    font-weight: bold;
                }}
                
                .filters {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 25px;
                }}
                
                .filters h2 {{
                    color: #764ba2;
                    margin-bottom: 15px;
                    font-size: 1.3em;
                }}
                
                .filter-row {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 15px;
                }}
                
                .filter-group {{
                    display: flex;
                    flex-direction: column;
                }}
                
                .filter-group label {{
                    color: #666;
                    font-size: 0.9em;
                    margin-bottom: 5px;
                    font-weight: 600;
                }}
                
                .filter-group select,
                .filter-group input {{
                    padding: 10px;
                    border: 2px solid #ddd;
                    border-radius: 6px;
                    font-size: 1em;
                    transition: border-color 0.3s;
                }}
                
                .filter-group select:focus,
                .filter-group input:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                
                .cp-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                
                .cp-card {{
                    background: #fff;
                    border: 2px solid #e0e0e0;
                    border-radius: 10px;
                    padding: 20px;
                    transition: all 0.3s;
                    cursor: pointer;
                    position: relative;
                }}
                
                .cp-card:hover {{
                    border-color: #667eea;
                    box-shadow: 0 8px 20px rgba(102,126,234,0.3);
                    transform: translateY(-3px);
                }}
                
                .cp-card.favorite {{
                    border-color: #ffd700;
                    background: #fffef0;
                }}
                
                .cp-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 15px;
                }}
                
                .cp-id {{
                    font-size: 1.3em;
                    font-weight: bold;
                    color: #333;
                }}
                
                .cp-name {{
                    color: #666;
                    font-size: 0.9em;
                    margin-top: 2px;
                }}
                
                .favorite-btn {{
                    background: none;
                    border: none;
                    font-size: 1.8em;
                    cursor: pointer;
                    color: #ccc;
                    transition: all 0.3s;
                }}
                
                .favorite-btn.active {{
                    color: #ffd700;
                    transform: scale(1.2);
                }}
                
                .favorite-btn:hover {{
                    transform: scale(1.3);
                }}
                
                .status-badge {{
                    display: inline-block;
                    padding: 6px 14px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: bold;
                    text-transform: uppercase;
                    margin-bottom: 12px;
                }}
                
                .status-FREE {{ background: #4caf50; color: white; }}
                .status-OCCUPIED {{ background: #ff9800; color: white; }}
                .status-OFFLINE {{ background: #f44336; color: white; }}
                
                .cp-location {{
                    color: #667eea;
                    font-weight: 600;
                    margin-bottom: 12px;
                    font-size: 0.95em;
                }}
                
                .cp-details {{
                    color: #666;
                    line-height: 1.8;
                    font-size: 0.95em;
                }}
                
                .cp-detail-row {{
                    display: flex;
                    justify-content: space-between;
                    margin: 8px 0;
                    padding: 5px 0;
                    border-bottom: 1px solid #f0f0f0;
                }}
                
                .cp-detail-row:last-child {{
                    border-bottom: none;
                }}
                
                .request-btn {{
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 1em;
                    font-weight: 600;
                    margin-top: 15px;
                    width: 100%;
                    transition: all 0.3s;
                }}
                
                .request-btn:hover {{
                    background: #5568d3;
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102,126,234,0.4);
                }}
                
                .request-btn:disabled {{
                    background: #ccc;
                    cursor: not-allowed;
                    transform: none;
                    box-shadow: none;
                }}
                
                .stop-btn {{
                    background: #f44336;
                }}
                
                .stop-btn:hover {{
                    background: #da190b;
                }}
                
                .cancel-btn {{
                    background: #ff9800;
                }}
                
                .cancel-btn:hover {{
                    background: #f57c00;
                }}
                
                .section-header {{
                    color: #764ba2;
                    margin: 30px 0 15px 0;
                    font-size: 1.5em;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .count-badge {{
                    background: #e0e0e0;
                    color: #666;
                    padding: 5px 12px;
                    border-radius: 15px;
                    font-size: 0.7em;
                }}
                
                .notifications {{
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    max-width: 400px;
                    z-index: 1000;
                }}
                
                .notification {{
                    background: white;
                    padding: 18px;
                    border-radius: 8px;
                    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
                    margin-bottom: 12px;
                    border-left: 5px solid #667eea;
                    animation: slideIn 0.4s ease-out;
                }}
                
                @keyframes slideIn {{
                    from {{
                        transform: translateX(450px);
                        opacity: 0;
                    }}
                    to {{
                        transform: translateX(0);
                        opacity: 1;
                    }}
                }}
                
                .notification.success {{ border-left-color: #4caf50; }}
                .notification.error {{ border-left-color: #f44336; }}
                .notification.warning {{ border-left-color: #ff9800; }}
                
                .notification-title {{
                    font-weight: bold;
                    margin-bottom: 5px;
                    text-transform: uppercase;
                    font-size: 0.85em;
                }}
                
                .empty-state {{
                    text-align: center;
                    padding: 60px 20px;
                    color: #999;
                }}
                
                .empty-state-icon {{
                    font-size: 4em;
                    margin-bottom: 15px;
                }}
                
                .btn-group {{
                    display: flex;
                    gap: 10px;
                }}
                
                .btn-secondary {{
                    background: #9e9e9e;
                }}
                
                .btn-secondary:hover {{
                    background: #757575;
                }}
                
                @keyframes pulse {{
                    0%, 100% {{ opacity: 1; }}
                    50% {{ opacity: 0.6; }}
                }}
                
                .charging-indicator {{
                    animation: pulse 2s infinite;
                }}
                
                /* Sync status indicator styles */
                .sync-status {{
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 12px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: 500;
                }}
                
                .sync-status.connected {{
                    background: #e8f5e9;
                    color: #2e7d32;
                }}
                
                .sync-status.disconnected {{
                    background: #fff3e0;
                    color: #e65100;
                }}
                
                .sync-status.stale {{
                    background: #fff8e1;
                    color: #f57c00;
                }}
                
                .sync-dot {{
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    animation: pulse 2s infinite;
                }}
                
                .sync-dot.connected {{
                    background: #4caf50;
                }}
                
                .sync-dot.disconnected {{
                    background: #ff5722;
                }}
                
                .sync-dot.stale {{
                    background: #ff9800;
                }}
                
                .stale-warning {{
                    background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%);
                    border: 2px solid #ff9800;
                    border-radius: 8px;
                    padding: 15px;
                    margin-bottom: 20px;
                    display: none;
                }}
                
                .stale-warning.visible {{
                    display: block;
                }}
                
                .stale-warning h4 {{
                    color: #e65100;
                    margin-bottom: 8px;
                }}
                
                .stale-warning p {{
                    color: #f57c00;
                    margin: 0;
                    font-size: 0.9em;
                }}
                
                .stale-warning .reassurance {{
                    color: #2e7d32;
                    margin-top: 8px;
                    font-weight: 500;
                }}
                
                /* System Errors Section */
                .errors-section {{
                    background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 20px;
                    border-left: 5px solid #f44336;
                }}
                .errors-section.no-errors {{
                    background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
                    border-left-color: #4caf50;
                }}
                .errors-section h3 {{
                    color: #c62828;
                    margin-bottom: 15px;
                    font-size: 1.1em;
                }}
                .errors-section.no-errors h3 {{
                    color: #2e7d32;
                }}
                .error-item {{
                    background: white;
                    padding: 12px;
                    border-radius: 8px;
                    margin-bottom: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    border-left: 4px solid #f44336;
                }}
                .error-item.warning {{
                    border-left-color: #ff9800;
                }}
                .error-item.info {{
                    border-left-color: #2196f3;
                }}
                .error-message {{
                    font-weight: bold;
                    color: #333;
                    margin-bottom: 5px;
                    font-size: 0.95em;
                }}
                .error-detail {{
                    font-size: 0.85em;
                    color: #666;
                }}
                .error-meta {{
                    display: flex;
                    gap: 10px;
                    margin-top: 6px;
                    font-size: 0.8em;
                    color: #888;
                }}
                .error-badge {{
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-size: 0.7em;
                    font-weight: bold;
                    text-transform: uppercase;
                }}
                .error-badge.critical {{ background: #b71c1c; color: white; }}
                .error-badge.error {{ background: #f44336; color: white; }}
                .error-badge.warning {{ background: #ff9800; color: white; }}
                .error-badge.info {{ background: #2196f3; color: white; }}
                
                /* Weather styles */
                .weather {{
                    margin-top: 10px;
                    padding: 8px;
                    border-radius: 6px;
                    font-size: 0.9em;
                }}
                .weather-ok {{
                    background: #e8f5e9;
                    color: #2e7d32;
                }}
                .weather-alert {{
                    background: #ffebee;
                    color: #c62828;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                    <span>🚗 Driver Dashboard</span>
                    <span class="driver-badge">{driver_id}</span>
                </h1>
                
                <div class="status-bar">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span>📡 Real-time updates enabled</span>
                        <div id="sync-status" class="sync-status connected">
                            <span class="sync-dot connected"></span>
                            <span id="sync-text">Central connected</span>
                        </div>
                    </div>
                    <span class="last-update">Last sync: <span id="last-update">--:--:--</span></span>
                </div>
                
                <!-- Stale Data Warning Banner -->
                <div id="stale-warning" class="stale-warning">
                    <h4>⚠️ Central Dashboard Unavailable</h4>
                    <p>Unable to fetch latest charging point status. Displayed data may be outdated.</p>
                    <p class="reassurance">✅ Your charging requests and sessions continue to work normally via Kafka.</p>
                </div>
                
                <!-- System Errors Section -->
                <div id="errors-section" class="errors-section no-errors">
                    <h3>🚨 System Alerts & Errors</h3>
                    <div id="errors-list">
                        <p style="color: #2e7d32; text-align: center;">✅ All systems operational</p>
                    </div>
                </div>
                
                <!-- Active Session -->
                <div id="active-session-container"></div>
                
                <!-- Filters -->
                <div class="filters">
                    <h2>🔍 Find Charging Points</h2>
                    <div class="filter-row">
                        <div class="filter-group">
                            <label>📍 City</label>
                            <input type="text" id="filter-city" placeholder="Enter city">
                        </div>
                        <div class="filter-group">
                            <label>🔌 Connector Type</label>
                            <select id="filter-connector">
                                <option value="">All Connectors</option>
                                <option value="Type 2">Type 2</option>
                                <option value="CCS">CCS</option>
                                <option value="CHAdeMO">CHAdeMO</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>⚡ Min Power (kW)</label>
                            <input type="number" id="filter-min-power" placeholder="0" min="0">
                        </div>
                        <div class="filter-group">
                            <label>📊 Status</label>
                            <select id="filter-status">
                                <option value="">All Status</option>
                                <option value="FREE">Available</option>
                                <option value="OCCUPIED">Occupied</option>
                                <option value="OFFLINE">Offline</option>
                            </select>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button class="request-btn" onclick="applyFilters()" style="width: auto;">Apply Filters</button>
                        <button class="request-btn btn-secondary" onclick="clearFilters()" style="width: auto;">Clear</button>
                    </div>
                </div>
                
                <!-- Favorites Section -->
                <div id="favorites-section" style="display: none;">
                    <h2 class="section-header">
                        <span>⭐ Favorite Charging Points</span>
                        <span class="count-badge" id="favorites-count">0</span>
                    </h2>
                    <div class="cp-grid" id="favorites-grid"></div>
                </div>
                
                <!-- All Charging Points -->
                <h2 class="section-header">
                    <span>⚡ All Charging Points</span>
                    <span class="count-badge" id="cp-count">0</span>
                </h2>
                <div class="cp-grid" id="cp-grid"></div>
            </div>
            
            <!-- Notifications Container -->
            <div class="notifications" id="notifications"></div>
            
            <script>
                const driverId = '{driver_id}';
                let chargingPoints = [];
                let favorites = new Set();
                let activeSession = null;
                let weatherCache = {{}};
                let lastWeatherFetch = 0;
                const WEATHER_FETCH_INTERVAL = 10000; // 10 seconds
                
                function showNotification(message, type = 'info') {{
                    try {{
                        const container = document.getElementById('notifications');
                        if (!container) return;
                        const notification = document.createElement('div');
                        notification.className = `notification ${{type}}`;
                        notification.innerHTML = `
                            <div class="notification-title">${{type}}</div>
                            ${{message}}
                        `;
                        container.appendChild(notification);
                        
                        setTimeout(() => {{
                            try {{
                                notification.remove();
                            }} catch (e) {{
                                // Notification may already be removed
                            }}
                        }}, 5000);
                    }} catch (e) {{
                        console.warn('Could not show notification:', e.message);
                    }}
                }}
                
                // Fault-tolerant weather update - never throws
                async function updateWeather() {{
                    try {{
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), 5000);
                        
                        const response = await fetch('/weather', {{ signal: controller.signal }});
                        clearTimeout(timeoutId);
                        
                        if (!response.ok) {{
                            console.warn('Weather service returned error:', response.status);
                            return; // Don't clear cache, keep old data
                        }}
                        
                        const data = await response.json();
                        if (data && typeof data.weather === 'object') {{
                            weatherCache = data.weather || {{}};
                            const weatherCount = Object.keys(weatherCache).length;
                            if (weatherCount > 0) {{
                                console.log('Weather data loaded:', weatherCount, 'cities');
                            }} else {{
                                console.info('Weather service connected but no weather data available yet');
                            }}
                        }}
                    }} catch (error) {{
                        // Weather service unavailable - this is expected and non-critical
                        // Dashboard continues to function normally without weather data
                        // Don't clear weatherCache - keep stale data if available
                        if (error.name === 'AbortError') {{
                            console.debug('Weather request timed out');
                        }} else {{
                            console.debug('Weather service not available:', error.message);
                        }}
                    }}
                }}
                
                async function loadChargingPoints() {{
                    // Fetch weather if enough time has passed (fire and forget, don't block)
                    const now = Date.now();
                    if (now - lastWeatherFetch > WEATHER_FETCH_INTERVAL) {{
                        lastWeatherFetch = now;
                        updateWeather(); // Don't await, let it run in background
                    }}
                    try {{
                        console.log('[DEBUG] Fetching charging points...');
                        const response = await fetch('/charging-points');
                        console.log('[DEBUG] Response status:', response.status);
                        if (!response.ok) {{
                            throw new Error(`HTTP error! status: ${{response.status}}`);
                        }}
                        const data = await response.json();
                        console.log('[DEBUG] Loaded charging points:', data.length, 'items');
                        console.log('[DEBUG] First CP:', data[0]);
                        if (!Array.isArray(data)) {{
                            console.error('[DEBUG] Data is not an array!', typeof data);
                            throw new Error('Expected array of charging points');
                        }}
                        chargingPoints = data;
                        console.log('[DEBUG] Calling renderChargingPoints...');
                        renderChargingPoints();
                        console.log('[DEBUG] renderChargingPoints completed');
                    }} catch (error) {{
                        console.error('[ERROR] Error loading charging points:', error);
                        console.error('[ERROR] Stack:', error.stack);
                        showNotification('Failed to load charging points', 'error');
                    }}
                }}
                
                async function loadFavorites() {{
                    try {{
                        const response = await fetch(`/drivers/${{driverId}}/favorites`);
                        const data = await response.json();
                        favorites = new Set(data.map(cp => cp.cp_id));
                        renderFavorites(data);
                    }} catch (error) {{
                        console.error('Error loading favorites:', error);
                    }}
                }}
                
                function renderFavorites(favCps) {{
                    const container = document.getElementById('favorites-section');
                    const grid = document.getElementById('favorites-grid');
                    const count = document.getElementById('favorites-count');
                    
                    if (favCps.length === 0) {{
                        container.style.display = 'none';
                        return;
                    }}
                    
                    container.style.display = 'block';
                    count.textContent = favCps.length;
                    grid.innerHTML = favCps.map(cp => renderCpCard(cp)).join('');
                }}
                
                function renderChargingPoints() {{
                    console.log('[DEBUG] renderChargingPoints called, chargingPoints.length:', chargingPoints.length);
                    const grid = document.getElementById('cp-grid');
                    const count = document.getElementById('cp-count');
                    
                    console.log('[DEBUG] grid element:', grid);
                    console.log('[DEBUG] count element:', count);
                    
                    count.textContent = chargingPoints.length;
                    
                    if (chargingPoints.length === 0) {{
                        console.log('[DEBUG] No charging points, showing empty state');
                        grid.innerHTML = `
                            <div class="empty-state" style="grid-column: 1 / -1;">
                                <div class="empty-state-icon">🔍</div>
                                <div>No charging points found</div>
                            </div>
                        `;
                        return;
                    }}
                    
                    console.log('[DEBUG] Rendering', chargingPoints.length, 'charging points...');
                    try {{
                        const cards = chargingPoints.map(cp => renderCpCard(cp));
                        console.log('[DEBUG] Generated', cards.length, 'cards');
                        grid.innerHTML = cards.join('');
                        console.log('[DEBUG] Cards rendered to grid');
                    }} catch (error) {{
                        console.error('[ERROR] Error rendering cards:', error);
                        console.error('[ERROR] Stack:', error.stack);
                    }}
                }}
                
                function renderCpCard(cp) {{
                    const isFavorite = favorites.has(cp.cp_id);
                    const isDisabled = cp.status !== 'FREE' || activeSession;
                    
                    return `
                        <div class="cp-card ${{isFavorite ? 'favorite' : ''}}">
                            <div class="cp-header">
                                <div>
                                    <div class="cp-id">${{cp.cp_id}}</div>
                                    <div class="cp-name">${{cp.name}}</div>
                                </div>
                                <button 
                                    class="favorite-btn ${{isFavorite ? 'active' : ''}}" 
                                    onclick="toggleFavorite('${{cp.cp_id}}')"
                                    title="${{isFavorite ? 'Remove from favorites' : 'Add to favorites'}}"
                                >★</button>
                            </div>
                            
                            <span class="status-badge status-${{cp.status}}">${{cp.status}}</span>
                            
                            ${{(() => {{
                                if (cp.location.city && weatherCache[cp.location.city] && typeof weatherCache[cp.location.city].temperature === 'number') {{
                                    const w = weatherCache[cp.location.city];
                                    const tempAlert = w.temperature > 35 || w.temperature < 0;
                                    const cssClass = tempAlert ? 'weather-alert' : 'weather-ok';
                                    return `<div class="weather ${{cssClass}}">🌡️ ${{cp.location.city}}: ${{w.temperature.toFixed(1)}}°C - ${{w.description || 'N/A'}}</div>`;
                                }} else if (cp.location.city) {{
                                    // Just show city name without "loading" message
                                    return `<div class="weather">📍 ${{cp.location.city}}</div>`;
                                }}
                                return '';
                            }})()}}
                            
                            <div class="cp-details">
                                <div class="cp-detail-row">
                                    <span>🔌 Connector:</span>
                                    <strong>${{cp.connector_type}}</strong>
                                </div>
                                <div class="cp-detail-row">
                                    <span>⚡ Power:</span>
                                    <strong>${{cp.power_kw}} kW</strong>
                                </div>
                                ${{cp.price_eur_per_kwh ? `
                                <div class="cp-detail-row">
                                    <span>💰 Price:</span>
                                    <strong>€${{cp.price_eur_per_kwh.toFixed(2)}}/kWh</strong>
                                </div>
                                ` : ''}}
                                ${{cp.distance_km ? `
                                <div class="cp-detail-row">
                                    <span>📏 Distance:</span>
                                    <strong>${{cp.distance_km.toFixed(1)}} km</strong>
                                </div>
                                ` : ''}}
                                ${{cp.queue_length > 0 ? `
                                <div class="cp-detail-row">
                                    <span>⏳ Queue:</span>
                                    <strong>${{cp.queue_length}} waiting</strong>
                                </div>
                                <div class="cp-detail-row">
                                    <span>⏱️ Wait Time:</span>
                                    <strong>~${{cp.estimated_wait_minutes}} min</strong>
                                </div>
                                ` : ''}}
                            </div>
                            
                            <button 
                                class="request-btn" 
                                onclick="requestSession('${{cp.cp_id}}')"
                                ${{isDisabled ? 'disabled' : ''}}
                            >
                                ${{activeSession ? '⏳ Session Active' : cp.status === 'FREE' ? '⚡ Start Charging' : '⏳ ' + cp.status}}
                            </button>
                        </div>
                    `;
                }}
                
                async function loadActiveSession() {{
                    try {{
                        const response = await fetch(`/drivers/${{driverId}}/sessions/current`);
                        const data = await response.json();
                        activeSession = data;
                        renderActiveSession();
                        loadChargingPoints(); // Refresh to update button states
                    }} catch (error) {{
                        console.error('Error loading active session:', error);
                    }}
                }}
                
                function renderActiveSession() {{
                    const container = document.getElementById('active-session-container');
                    
                    if (!activeSession) {{
                        container.innerHTML = '';
                        return;
                    }}
                    
                    const statusDisplay = {{
                        'PENDING': '⏳ Pending Approval',
                        'APPROVED': '✅ Approved - Starting',
                        'CHARGING': '🔋 Charging',
                        'COMPLETED': '✔️ Completed',
                        'DENIED': '❌ Denied',
                        'FAILED': '⚠️ Failed',
                        'STOPPED': '⏹️ Stopped',
                        'CANCELLED': '🚫 Cancelled'
                    }}[activeSession.status] || activeSession.status;
                    
                    const actionBtn = activeSession.status === 'PENDING' 
                        ? `<button class="request-btn cancel-btn" onclick="cancelSession('${{activeSession.request_id}}')">❌ Cancel Request</button>`
                        : (activeSession.status === 'CHARGING' || activeSession.status === 'APPROVED')
                        ? `<button class="request-btn stop-btn" onclick="stopSession('${{activeSession.session_id}}')">⏹️ End Charging Session</button>`
                        : '';
                    
                    const isCharging = activeSession.status === 'CHARGING';
                    
                    container.innerHTML = `
                        <div class="active-session ${{isCharging ? 'charging-indicator' : ''}}">
                            <h3>🔋 Active Session: ${{activeSession.session_id}}</h3>
                            <div class="session-info">
                                <div class="info-item">
                                    <div class="info-label">Status</div>
                                    <div class="info-value">${{statusDisplay}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Charging Point</div>
                                    <div class="info-value">${{activeSession.cp_id}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Energy</div>
                                    <div class="info-value">${{(activeSession.energy_kwh || 0).toFixed(2)}} kWh</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Cost</div>
                                    <div class="info-value">€${{(activeSession.cost_eur || 0).toFixed(4)}}</div>
                                </div>
                                ${{activeSession.started_at ? `
                                <div class="info-item">
                                    <div class="info-label">Started</div>
                                    <div class="info-value" style="font-size: 0.9em;">${{new Date(activeSession.started_at).toLocaleTimeString()}}</div>
                                </div>
                                ` : ''}}
                            </div>
                            ${{actionBtn}}
                        </div>
                    `;
                }}
                
                async function requestSession(cpId) {{
                    try {{
                        const response = await fetch(`/drivers/${{driverId}}/requests`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{
                                cp_id: cpId,
                                vehicle_id: 'vehicle-1'
                            }})
                        }});
                        
                        if (response.ok) {{
                            const data = await response.json();
                            showNotification(`Charging requested at ${{cpId}}`, 'success');
                            loadActiveSession();
                        }} else {{
                            showNotification('Failed to request session', 'error');
                        }}
                    }} catch (error) {{
                        console.error('Error requesting session:', error);
                        showNotification('Error requesting session', 'error');
                    }}
                }}
                
                async function cancelSession(requestId) {{
                    try {{
                        const response = await fetch(`/drivers/${{driverId}}/requests/${{requestId}}`, {{
                            method: 'DELETE'
                        }});
                        
                        if (response.ok) {{
                            showNotification('Session request cancelled', 'success');
                            loadActiveSession();
                        }} else {{
                            showNotification('Failed to cancel request', 'error');
                        }}
                    }} catch (error) {{
                        console.error('Error cancelling session:', error);
                        showNotification('Error cancelling session', 'error');
                    }}
                }}
                
                async function stopSession(sessionId) {{
                    try {{
                        const response = await fetch(`/drivers/${{driverId}}/sessions/${{sessionId}}/stop`, {{
                            method: 'POST'
                        }});
                        
                        if (response.ok) {{
                            showNotification('Charging session stopped', 'success');
                            loadActiveSession();
                        }} else {{
                            showNotification('Failed to stop session', 'error');
                        }}
                    }} catch (error) {{
                        console.error('Error stopping session:', error);
                        showNotification('Error stopping session', 'error');
                    }}
                }}
                
                async function toggleFavorite(cpId) {{
                    const isFavorite = favorites.has(cpId);
                    const method = isFavorite ? 'DELETE' : 'POST';
                    const url = isFavorite 
                        ? `/drivers/${{driverId}}/favorites/${{cpId}}`
                        : `/drivers/${{driverId}}/favorites`;
                    
                    try {{
                        const response = await fetch(url, {{
                            method: method,
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: method === 'POST' ? JSON.stringify({{ cp_id: cpId }}) : undefined
                        }});
                        
                        if (response.ok) {{
                            if (isFavorite) {{
                                favorites.delete(cpId);
                                showNotification(`${{cpId}} removed from favorites`, 'info');
                            }} else {{
                                favorites.add(cpId);
                                showNotification(`${{cpId}} added to favorites`, 'success');
                            }}
                            loadFavorites();
                            renderChargingPoints();
                        }}
                    }} catch (error) {{
                        console.error('Error toggling favorite:', error);
                        showNotification('Error updating favorites', 'error');
                    }}
                }}
                
                async function applyFilters() {{
                    const city = document.getElementById('filter-city').value;
                    const connector = document.getElementById('filter-connector').value;
                    const minPower = document.getElementById('filter-min-power').value;
                    const status = document.getElementById('filter-status').value;
                    
                    const params = new URLSearchParams();
                    if (city) params.append('city', city);
                    if (connector) params.append('connector_type', connector);
                    if (minPower) params.append('min_power_kw', minPower);
                    if (status === 'FREE') params.append('only_available', 'true');
                    
                    try {{
                        const response = await fetch(`/charging-points?${{params}}`);
                        if (!response.ok) {{
                            throw new Error(`HTTP error! status: ${{response.status}}`);
                        }}
                        const data = await response.json();
                        console.log('Filtered charging points:', data);
                        if (!Array.isArray(data)) {{
                            throw new Error('Expected array of charging points');
                        }}
                        chargingPoints = data;
                        renderChargingPoints();
                        showNotification(`Found ${{data.length}} charging points`, 'info');
                    }} catch (error) {{
                        console.error('Error applying filters:', error);
                        showNotification('Error applying filters: ' + error.message, 'error');
                    }}
                }}
                
                function clearFilters() {{
                    document.getElementById('filter-city').value = '';
                    document.getElementById('filter-connector').value = '';
                    document.getElementById('filter-min-power').value = '';
                    document.getElementById('filter-status').value = '';
                    loadChargingPoints();
                }}
                
                function updateTimestamp(lastSync) {{
                    if (lastSync) {{
                        const date = new Date(lastSync);
                        document.getElementById('last-update').textContent = date.toLocaleTimeString();
                    }} else {{
                        document.getElementById('last-update').textContent = '--:--:--';
                    }}
                }}
                
                async function updateSyncStatus() {{
                    try {{
                        const response = await fetch('/sync-status');
                        const status = await response.json();
                        
                        const syncStatusEl = document.getElementById('sync-status');
                        const syncTextEl = document.getElementById('sync-text');
                        const syncDotEl = syncStatusEl.querySelector('.sync-dot');
                        const staleWarningEl = document.getElementById('stale-warning');
                        
                        // Update timestamp from sync status
                        updateTimestamp(status.last_sync);
                        
                        if (status.central_connected && !status.is_stale) {{
                            // Connected and fresh
                            syncStatusEl.className = 'sync-status connected';
                            syncDotEl.className = 'sync-dot connected';
                            syncTextEl.textContent = 'Central connected';
                            staleWarningEl.classList.remove('visible');
                        }} else if (status.central_connected && status.is_stale) {{
                            // Connected but data is stale
                            syncStatusEl.className = 'sync-status stale';
                            syncDotEl.className = 'sync-dot stale';
                            syncTextEl.textContent = `Data ${{Math.round(status.age_seconds)}}s old`;
                            staleWarningEl.classList.remove('visible');
                        }} else {{
                            // Disconnected
                            syncStatusEl.className = 'sync-status disconnected';
                            syncDotEl.className = 'sync-dot disconnected';
                            const failCount = status.consecutive_failures;
                            syncTextEl.textContent = `Central unreachable (${{failCount}} failures)`;
                            staleWarningEl.classList.add('visible');
                        }}
                    }} catch (error) {{
                        console.error('Error fetching sync status:', error);
                    }}
                }}
                
                // Initialize - await weather first, then render dashboard
                (async function() {{
                    console.log('[INIT] Starting dashboard initialization...');
                    try {{
                        console.log('[INIT] Loading weather data...');
                        await updateWeather(); // Load weather data first (fault-tolerant)
                        lastWeatherFetch = Date.now(); // Reset timer after initial fetch
                        console.log('[INIT] Weather loaded, now loading charging points...');
                    }} catch (weatherError) {{
                        console.error('[INIT] Weather failed, continuing anyway:', weatherError);
                    }}
                    
                    try {{
                        console.log('[INIT] Calling loadChargingPoints...');
                        await loadChargingPoints(); // Then render with weather data
                        console.log('[INIT] loadChargingPoints completed');
                    }} catch (cpError) {{
                        console.error('[INIT] loadChargingPoints failed:', cpError);
                    }}
                    
                    // Load other components (each is fault-tolerant)
                    try {{ loadActiveSession(); }} catch (e) {{ console.warn('loadActiveSession error:', e); }}
                    try {{ loadFavorites(); }} catch (e) {{ console.warn('loadFavorites error:', e); }}
                    try {{ updateSyncStatus(); }} catch (e) {{ console.warn('updateSyncStatus error:', e); }}
                    try {{ loadErrors(); }} catch (e) {{ console.warn('loadErrors error:', e); }}
                    console.log('[INIT] Initial load complete, starting intervals...');
                    
                    // Auto-refresh every 2 seconds (each call is fault-tolerant)
                    setInterval(() => {{
                        try {{ loadChargingPoints(); }} catch (e) {{ console.warn('loadChargingPoints interval error:', e); }}
                        try {{ loadActiveSession(); }} catch (e) {{ console.warn('loadActiveSession interval error:', e); }}
                        try {{ updateSyncStatus(); }} catch (e) {{ console.warn('updateSyncStatus interval error:', e); }}
                        try {{ loadErrors(); }} catch (e) {{ console.warn('loadErrors interval error:', e); }}
                    }}, 2000);
                    
                    // Refresh favorites every 10 seconds
                    setInterval(() => {{
                        try {{ loadFavorites(); }} catch (e) {{ console.warn('loadFavorites interval error:', e); }}
                    }}, 10000);
                }})();
                
                // Load and display system errors
                async function loadErrors() {{
                    try {{
                        const response = await fetch('/errors');
                        const data = await response.json();
                        updateErrorsDisplay(data.all_errors || []);
                    }} catch (error) {{
                        console.error('Error loading errors:', error);
                    }}
                }}
                
                function updateErrorsDisplay(errors) {{
                    const section = document.getElementById('errors-section');
                    const container = document.getElementById('errors-list');
                    if (!section || !container) return;
                    
                    const activeErrors = errors.filter(e => !e.resolved);
                    
                    if (activeErrors.length === 0) {{
                        section.classList.add('no-errors');
                        container.innerHTML = '<p style="color: #2e7d32; text-align: center;">✅ All systems operational</p>';
                        return;
                    }}
                    
                    section.classList.remove('no-errors');
                    
                    container.innerHTML = activeErrors.slice(0, 5).map(err => {{
                        const severityClass = err.severity.toLowerCase();
                        const badgeClass = err.severity === 'CRITICAL' ? 'critical' : 
                                          err.severity === 'ERROR' ? 'error' :
                                          err.severity === 'WARNING' ? 'warning' : 'info';
                        const timestamp = err.timestamp ? new Date(err.timestamp).toLocaleTimeString() : '';
                        return `
                            <div class="error-item ${{severityClass}}">
                                <div class="error-message">⚠️ ${{err.message}}</div>
                                ${{err.technical_detail ? `<div class="error-detail">${{err.technical_detail}}</div>` : ''}}
                                <div class="error-meta">
                                    <span class="error-badge ${{badgeClass}}">${{err.severity}}</span>
                                    <span>${{err.target || ''}}</span>
                                    <span>${{timestamp}}</span>
                                </div>
                            </div>
                        `;
                    }}).join('');
                }}
            </script>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)

    return app
