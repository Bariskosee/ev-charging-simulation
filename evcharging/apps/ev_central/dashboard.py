"""
Dashboard for EV Central - FastAPI web interface.
Provides real-time view of charging points and telemetry.

Security:
- CP endpoints support optional JWT authentication
- When authenticated, tokens are validated against Registry-issued credentials
- Unauthenticated access allowed for backward compatibility (lab mode)
"""

import asyncio
import os
from urllib.parse import quote

import aiohttp
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import TYPE_CHECKING, Optional
from loguru import logger

from evcharging.common.messages import CPRegistration, WeatherReport

if TYPE_CHECKING:
    from evcharging.apps.ev_central.main import EVCentralController


def create_dashboard_app(controller: "EVCentralController") -> FastAPI:
    """Create FastAPI application for dashboard."""
    
    app = FastAPI(title="EV Central Dashboard", version="0.1.0")
    
    async def verify_cp_token(
        authorization: Optional[str] = Header(None, alias="Authorization")
    ) -> Optional[dict]:
        """
        Verify JWT token from CP.
        Returns token claims if valid, None if no token provided.
        Raises HTTPException if token is invalid.
        
        This provides optional authentication - CPs with Registry tokens
        are validated, while unauthenticated access is allowed for
        backward compatibility.
        """
        if not authorization:
            return None  # No token - allow for backward compatibility
        
        # Extract Bearer token
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Invalid authorization header format"
            )
        
        token = authorization[7:]  # Remove "Bearer " prefix
        
        # Verify token using security manager
        try:
            claims = controller.security_manager.verify_access_token(token)
            if not claims:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired token"
                )
            logger.debug(f"Token verified for CP: {claims.get('sub')}")
            return claims
        except Exception as e:
            logger.warning(f"Token verification failed: {e}")
            raise HTTPException(
                status_code=401,
                detail="Token verification failed"
            )
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "service": "ev-central"}
    
    @app.post("/cp/register")
    async def register_cp(
        registration: CPRegistration,
        token_claims: Optional[dict] = Depends(verify_cp_token)
    ):
        """
        Register or update a charging point.
        
        Security: Accepts optional JWT token in Authorization header.
        If provided, token is validated against Registry-issued credentials.
        """
        # If token provided, validate CP ID matches
        if token_claims:
            token_cp_id = token_claims.get("sub")
            if token_cp_id and token_cp_id != registration.cp_id:
                logger.warning(
                    f"CP ID mismatch: token={token_cp_id}, request={registration.cp_id}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="CP ID in token does not match registration"
                )
            logger.info(f"Authenticated registration from CP {registration.cp_id}")
        
        success = controller.register_cp(registration)
        return {
            "success": success,
            "cp_id": registration.cp_id,
            "authenticated": token_claims is not None,
            "message": "Charging point registered successfully" if success else "Registration failed"
        }
    
    @app.delete("/cp/{cp_id}")
    async def delete_cp(cp_id: str):
        """
        Remove a charging point from Central's tracking.
        
        This removes the CP from in-memory state.
        Does not affect Registry - use Registry API for permanent deregistration.
        """
        if cp_id in controller.charging_points:
            del controller.charging_points[cp_id]
            logger.info(f"Removed CP {cp_id} from Central")
            return {"success": True, "message": f"CP {cp_id} removed from Central"}
        else:
            raise HTTPException(status_code=404, detail=f"CP {cp_id} not found")
    
    @app.post("/cp/fault")
    async def notify_fault(
        fault_data: dict,
        token_claims: Optional[dict] = Depends(verify_cp_token)
    ):
        """
        Receive fault/health notifications from CP monitors.
        
        Security: Accepts optional JWT token for authenticated notifications.
        """
        cp_id = fault_data.get("cp_id")
        status = fault_data.get("status")
        reason = fault_data.get("reason", "")
        
        # Validate CP ID if authenticated
        if token_claims:
            token_cp_id = token_claims.get("sub")
            if token_cp_id and token_cp_id != cp_id:
                raise HTTPException(
                    status_code=403,
                    detail="CP ID in token does not match fault notification"
                )
        
        logger.info(f"Received fault notification for {cp_id}: {status} - {reason}")
        
        # Update CP state if it exists
        if cp_id in controller.charging_points:
            if status == "FAULT":
                logger.warning(f"CP {cp_id} marked as faulty by monitor: {reason}")
                await controller.mark_cp_faulty(cp_id, reason)
            elif status == "HEALTHY":
                logger.info(f"CP {cp_id} health restored: {reason}")
                await controller.clear_cp_fault(cp_id)
        
        return {"success": True, "cp_id": cp_id, "status": status}

    @app.post("/cp/heartbeat")
    async def monitor_heartbeat(
        payload: dict,
        token_claims: Optional[dict] = Depends(verify_cp_token)
    ):
        """
        Receive heartbeat ping from CP Monitor.
        
        Security: 
        - Accepts optional JWT token for authenticated heartbeats.
        - If signature is present, verifies HMAC signature with encryption key.
        - Rejects CPs with key mismatch.
        """
        cp_id = payload.get("cp_id")
        if not cp_id:
            raise HTTPException(status_code=400, detail="cp_id required")
        
        # Validate CP ID if authenticated
        if token_claims:
            token_cp_id = token_claims.get("sub")
            if token_cp_id and token_cp_id != cp_id:
                raise HTTPException(
                    status_code=403,
                    detail="CP ID in token does not match heartbeat"
                )

        # Check if heartbeat includes signature for encryption key verification
        signature = payload.get("signature")
        signed_message = payload.get("signed_message")
        
        signature_valid = None  # None = no signature provided, True = valid, False = invalid
        signature_error = None
        
        if signature and signed_message:
            # Verify the signature using the CP's encryption key
            is_valid, error_msg = controller.verify_heartbeat_signature(cp_id, signed_message, signature)
            signature_valid = is_valid
            if not is_valid:
                signature_error = error_msg
                logger.error(
                    f"🔐 SECURITY ALERT: CP {cp_id} heartbeat signature FAILED. "
                    f"Error: {error_msg}. "
                    f"The CP may have an incorrect encryption key!"
                )
        else:
            # No signature provided - check if Central expects one (has key for this CP)
            if controller.cp_security.get_key_for_cp(cp_id):
                # Central has a key but CP didn't sign - this is a security issue!
                logger.error(
                    f"🔐 SECURITY ALERT: CP {cp_id} sent unsigned heartbeat but "
                    f"Central has encryption key configured! "
                    f"The CP may have an incorrect or missing encryption key."
                )
                signature_valid = False
                signature_error = "Unsigned heartbeat from CP with encryption configured"

        # Record the heartbeat (this will also handle encryption error state)
        controller.record_monitor_ping(cp_id, signature_valid=signature_valid, signature_error=signature_error)
        
        return {
            "success": True, 
            "cp_id": cp_id, 
            "authenticated": token_claims is not None,
            "signature_verified": signature_valid
        }
    
    @app.post("/stop-session")
    async def stop_session(payload: dict):
        """Handle driver-initiated session stop request."""
        cp_id = payload.get("cp_id")
        driver_id = payload.get("driver_id")
        session_id = payload.get("session_id")
        
        if not cp_id or not driver_id or not session_id:
            raise HTTPException(status_code=400, detail="cp_id, driver_id, and session_id required")
        
        logger.info(f"Received stop session request from driver {driver_id} for CP {cp_id}, session {session_id}")
        
        # Validate CP exists and session matches
        if cp_id not in controller.charging_points:
            raise HTTPException(status_code=404, detail="Charging point not found")
        
        cp = controller.charging_points[cp_id]
        
        if cp.current_session != session_id:
            logger.warning(f"Session mismatch: requested {session_id}, current {cp.current_session}")
            raise HTTPException(status_code=400, detail="Session ID mismatch")
        
        if cp.current_driver != driver_id:
            logger.warning(f"Driver mismatch: requested {driver_id}, current {cp.current_driver}")
            raise HTTPException(status_code=403, detail="Not authorized to stop this session")
        
        # Send STOP_SUPPLY command to CP Engine
        await controller.send_stop_supply_command(cp_id, "Driver requested stop")
        
        return {"success": True, "cp_id": cp_id, "session_id": session_id, "message": "Stop command sent"}

    @app.post("/cp/stop")
    async def stop_cp(payload: dict):
        """Manually stop a charging session from the dashboard."""
        cp_id = payload.get("cp_id")
        if not cp_id:
            raise HTTPException(status_code=400, detail="cp_id required")

        if cp_id not in controller.charging_points:
            raise HTTPException(status_code=404, detail="Charging point not found")

        logger.info(f"Manual stop requested for {cp_id} via dashboard")

        await controller.send_stop_supply_command(cp_id, reason="Manual stop from dashboard")

        return {"success": True, "message": f"Stop command sent to {cp_id}"}
    
    @app.get("/cp")
    async def list_charging_points():
        """List all charging points and their current state."""
        data = controller.get_dashboard_data()
        return {
            "charging_points": data["charging_points"],
            "active_requests": data["active_requests"],
            "active_requests_details": data.get("active_requests_details", []),
            "system_errors": data.get("system_errors", []),
            "error_summary": data.get("error_summary", {}),
            "system_events": data.get("system_events", []),
        }
    
    @app.get("/errors")
    async def list_errors():
        """Get all system errors for dashboard display."""
        data = controller.get_dashboard_data()
        return {
            "errors": data.get("system_errors", []),
            "summary": data.get("error_summary", {}),
            "system_events": data.get("system_events", []),
        }
    
    @app.get("/weather")
    async def get_weather():
        """Get weather data for all CP locations from weather service.
        
        Returns weather data if available, or gracefully degrades with empty data
        if the weather service is unreachable or returns errors.
        This endpoint NEVER crashes - it always returns a valid JSON response.
        """
        cities = set()
        weather_data = {}
        service_status = "ok"
        
        try:
            # Get all unique cities from charging points
            for cp in controller.charging_points.values():
                if hasattr(cp, 'city') and cp.city:
                    cities.add(cp.city)
        except Exception as e:
            logger.warning(f"Error getting cities from charging points: {e}")
            cities = set()
        
        try:
            # Fetch weather data from weather service
            weather_url = os.getenv('WEATHER_SERVICE_URL', 'http://ev-weather:8003')
            async with aiohttp.ClientSession() as session:
                try:
                    timeout = aiohttp.ClientTimeout(total=2)
                    async with session.get(f'{weather_url}/weather', timeout=timeout) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                locations = set(data.get("locations", []))
                                # Filter only cities we care about
                                for city in cities:
                                    if city in data.get('weather', {}):
                                        weather_data[city] = data['weather'][city]
                                missing_cities = [city for city in cities if city not in locations]
                                for city in missing_cities:
                                    try:
                                        await session.post(
                                            f"{weather_url}/api/locations/{quote(city)}",
                                            timeout=timeout
                                        )
                                    except Exception as e:
                                        logger.debug(f"Could not register weather location '{city}': {e}")
                            except (ValueError, KeyError) as json_error:
                                logger.warning(f"Weather service returned invalid JSON: {json_error}")
                                service_status = "degraded"
                        elif response.status == 401:
                            logger.warning(f"Weather service authentication failed (401) - invalid API key")
                            service_status = "auth_error"
                        else:
                            logger.warning(f"Weather service returned status {response.status}")
                            service_status = "degraded"
                except asyncio.TimeoutError:
                    logger.debug("Weather service request timed out")
                    service_status = "timeout"
                except aiohttp.ClientError as e:
                    logger.debug(f"Weather service connection failed: {e}")
                    service_status = "unavailable"
                except Exception as e:
                    logger.warning(f"Could not fetch weather data: {e}")
                    service_status = "error"
        except Exception as e:
            logger.warning(f"Error in weather endpoint: {e}")
            service_status = "error"
        
        # Always return success with available data (even if empty)
        return {
            "cities": list(cities),
            "weather": weather_data,
            "service_status": service_status
        }
    
    @app.get("/cp/{cp_id}")
    async def get_charging_point(cp_id: str):
        """Get detailed information about a specific charging point."""
        if cp_id not in controller.charging_points:
            return {"error": "Charging point not found"}, 404
        
        cp = controller.charging_points[cp_id]
        return {
            "cp_id": cp.cp_id,
            "state": cp.state.value,
            "current_driver": cp.current_driver,
            "current_session": cp.current_session,
            "last_update": cp.last_update.isoformat(),
            "telemetry": (
                {
                    "kw": cp.last_telemetry.kw,
                    "euros": cp.last_telemetry.euros,
                    "driver_id": cp.last_telemetry.driver_id,
                    "session_id": cp.last_telemetry.session_id,
                    "ts": cp.last_telemetry.ts.isoformat(),
                }
                if cp.last_telemetry
                else None
            ),
        }
    
    @app.get("/telemetry")
    async def get_telemetry():
        """Get current telemetry from all active charging sessions."""
        telemetry_list = []
        for cp in controller.charging_points.values():
            if cp.last_telemetry:
                telemetry_list.append({
                    "cp_id": cp.cp_id,
                    "kw": cp.last_telemetry.kw,
                    "euros": cp.last_telemetry.euros,
                    "driver_id": cp.last_telemetry.driver_id,
                    "session_id": cp.last_telemetry.session_id,
                    "ts": cp.last_telemetry.ts.isoformat(),
                })
        return {"telemetry": telemetry_list}

    @app.get("/cp/{cp_id}/city")
    async def get_city(cp_id: str):
        """Get location information about specific charing point."""
        if cp_id not in controller.charging_points:
            return {"error": "Charging point not found"}, 404
        
        cp = controller.charging_points[cp_id]

        return {
            "cp_id": cp.cp_id,
            "state": cp.city,
        }

    @app.post("/weather/alert")
    async def receive_alert(city: str, temp: float):
        """Receives alert notification about a given city and sends 
        the fault notification to each CP in the alerted city"""
        
        for cp in controller.charging_points.values():
            if cp.city == city and not cp.is_faulty:
                await controller.mark_cp_faulty(
                    cp.cp_id,
                    reason=f"Weather alert in {city}"
                )
        
        return {"success": True, "city": city, "tempearature": temp}

    @app.post("/weather/cancel_alert")
    async def receive_alert_cancel(city: str, temp: float):
        """Receives alert cancellation and clear the fault in the CPs 
        in the given city"""

        for cp in controller.charging_points.values():
            if cp.city == city and cp.is_faulty and cp.fault_reason == f"Weather alert in {city}":
                await controller.clear_cp_fault(cp.cp_id)
        
        return {"success": True, "city": city, "temperature": temp}
    
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home(request: Request):
        """Main dashboard HTML page."""
        data = controller.get_dashboard_data()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>EV Central Dashboard</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 12px;
                    padding: 30px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                }}
                h1 {{
                    color: #667eea;
                    margin-top: 0;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 15px;
                }}
                .stats {{
                    display: flex;
                    gap: 20px;
                    margin: 20px 0;
                    flex-wrap: wrap;
                }}
                .stat-card {{
                    flex: 1;
                    min-width: 200px;
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                }}
                .stat-value {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #667eea;
                }}
                .stat-label {{
                    color: #666;
                    margin-top: 5px;
                }}
                .cp-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 20px;
                    margin-top: 30px;
                }}
                .cp-card {{
                    background: #fff;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    padding: 20px;
                    transition: all 0.3s;
                }}
                .cp-card:hover {{
                    border-color: #667eea;
                    box-shadow: 0 5px 15px rgba(102,126,234,0.3);
                    transform: translateY(-2px);
                }}
                .cp-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }}
                .cp-id {{
                    font-size: 1.2em;
                    font-weight: bold;
                    color: #333;
                }}
                .state-badge {{
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: bold;
                    text-transform: uppercase;
                }}
                .stop-btn {{
                    background: #f44336;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: bold;
                    margin-top: 10px;
                    width: 100%;
                    transition: background 0.2s;
                }}
                .stop-btn:hover {{
                    background: #d32f2f;
                }}
                .state-ACTIVATED {{ background: #4caf50; color: white; }}
                .state-SUPPLYING {{ background: #2196f3; color: white; animation: pulse 2s infinite; }}
                .state-STOPPED {{ background: #ff9800; color: white; }}
                .state-FAULT {{ background: #f44336; color: white; }}
                .state-DISCONNECTED {{ background: #9e9e9e; color: white; }}
                .state-ON {{ background: #4caf50; color: white; }}
                .state-BROKEN {{ background: #f44336; color: white; }}
                .state-ENCRYPTION_ERROR {{ 
                    background: linear-gradient(135deg, #b71c1c 0%, #d32f2f 100%);
                    color: white;
                    animation: pulse-error 1.5s ease-in-out infinite;
                }}
                @keyframes pulse-error {{
                    0%, 100% {{ opacity: 1; transform: scale(1); }}
                    50% {{ opacity: 0.85; transform: scale(1.05); }}
                }}
                /* Encryption error card styling */
                .cp-card.encryption-error {{
                    border: 3px solid #d32f2f;
                    box-shadow: 0 0 15px rgba(211, 47, 47, 0.3);
                    background: linear-gradient(180deg, #fff 0%, #ffebee 100%);
                }}
                .encryption-warning {{
                    background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
                    color: #b71c1c;
                    padding: 10px 12px;
                    border-radius: 6px;
                    font-size: 0.85em;
                    margin: 10px 0;
                    border-left: 4px solid #d32f2f;
                    font-weight: 500;
                }}
                @keyframes pulse {{
                    0%, 100% {{ opacity: 1; }}
                    50% {{ opacity: 0.7; }}
                }}
                /* Error section styles */
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
                .errors-section h2 {{
                    color: #c62828;
                    margin-bottom: 15px;
                }}
                .errors-section.no-errors h2 {{
                    color: #2e7d32;
                }}
                .error-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    border-left: 4px solid #f44336;
                }}
                .error-item.warning {{
                    border-left-color: #ff9800;
                }}
                .error-item.info {{
                    border-left-color: #2196f3;
                }}
                .error-content {{
                    flex: 1;
                }}
                .error-message {{
                    font-weight: bold;
                    color: #333;
                    margin-bottom: 5px;
                }}
                .error-detail {{
                    font-size: 0.9em;
                    color: #666;
                }}
                .error-meta {{
                    display: flex;
                    gap: 15px;
                    margin-top: 8px;
                    font-size: 0.85em;
                    color: #888;
                }}
                .error-badge {{
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 0.75em;
                    font-weight: bold;
                    text-transform: uppercase;
                }}
                .error-badge.critical {{ background: #b71c1c; color: white; }}
                .error-badge.error {{ background: #f44336; color: white; }}
                .error-badge.warning {{ background: #ff9800; color: white; }}
                .error-badge.info {{ background: #2196f3; color: white; }}
                .error-summary {{
                    display: flex;
                    gap: 10px;
                    flex-wrap: wrap;
                    margin-bottom: 15px;
                }}
                .error-stat {{
                    background: white;
                    padding: 10px 15px;
                    border-radius: 6px;
                    font-size: 0.9em;
                }}
                .error-stat span {{
                    font-weight: bold;
                    color: #f44336;
                }}
                .state-STOPPED {{ background: #ff9800; color: white; }}
                .state-FAULT {{ background: #f44336; color: white; }}
                .state-DISCONNECTED {{ background: #9e9e9e; color: white; }}
                .state-ON {{ background: #4caf50; color: white; }}
                .state-BROKEN {{ background: #f44336; color: white; }}
                @keyframes pulse {{
                    0%, 100% {{ opacity: 1; }}
                    50% {{ opacity: 0.7; }}
                }}
                .telemetry {{
                    background: #f0f4ff;
                    padding: 12px;
                    border-radius: 6px;
                    margin-top: 10px;
                }}
                .telemetry-row {{
                    display: flex;
                    justify-content: space-between;
                    margin: 5px 0;
                }}
                .telemetry-label {{
                    color: #666;
                    font-weight: 500;
                }}
                .telemetry-value {{
                    color: #222;
                    font-weight: bold;
                }}
                .driver-info {{
                    color: #667eea;
                    font-style: italic;
                    margin-top: 10px;
                }}
                .active-sessions {{
                    background: #e3f2fd;
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 30px;
                    border-left: 5px solid #2196f3;
                }}
                .active-sessions h2 {{
                    color: #1976d2;
                    margin-bottom: 15px;
                }}
                .request-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 10px;
                }}
                .request-info {{
                    display: flex;
                    gap: 10px;
                    align-items: center;
                }}
                .request-meta {{
                    display: flex;
                    gap: 15px;
                    color: #666;
                    font-size: 0.9em;
                }}
                .request-id {{
                    font-family: monospace;
                }}
                .stop-btn-small {{
                    background: #e53935;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 0.9em;
                    font-weight: bold;
                    transition: background 0.2s;
                }}
                .stop-btn-small:hover {{
                    background: #c62828;
                }}
                .refresh-btn {{
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 1em;
                    margin-top: 20px;
                }}
                .refresh-btn:hover {{
                    background: #5568d3;
                }}
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
            <script>
                // Fetch and update data without page reload
                function formatTime(ts) {{
                    if (!ts) return 'Unknown';
                    try {{
                        const date = new Date(ts);
                        return date.toLocaleTimeString();
                    }} catch (e) {{
                        return 'Unknown';
                    }}
                }}

                // Fetch weather data - fault tolerant, never throws
                let weatherCache = {{}};
                let lastWeatherFetch = 0;
                const WEATHER_FETCH_INTERVAL = 4000; // 4 seconds
                
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
                                console.log('Weather updated:', weatherCount, 'cities');
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

                async function updateDashboard() {{
                    // Fetch weather if enough time has passed
                    const now = Date.now();
                    if (now - lastWeatherFetch > WEATHER_FETCH_INTERVAL) {{
                        lastWeatherFetch = now;
                        updateWeather(); // Don't await, let it run in background
                    }}
                    try {{
                        const response = await fetch('/cp');
                        const data = await response.json();
                        
                        // Update stats
                        document.getElementById('total-cps').textContent = data.charging_points.length;
                        document.getElementById('active-requests').textContent = data.active_requests;
                        document.getElementById('currently-charging').textContent = 
                            data.charging_points.filter(cp => cp.engine_state === 'SUPPLYING').length;
                        
                        // Update CP cards
                        const cpGrid = document.getElementById('cp-grid');
                        cpGrid.innerHTML = '';
                        
                        data.charging_points.forEach(cp => {{
                            const card = document.createElement('div');
                            // Add encryption-error class if CP has encryption issue
                            const isEncryptionError = cp.communication_status === 'ENCRYPTION_ERROR' || cp.state === 'ENCRYPTION_ERROR';
                            card.className = isEncryptionError ? 'cp-card encryption-error' : 'cp-card';
                            
                            let telemetryRows = '';
                            if (cp.telemetry) {{
                                telemetryRows = `
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Power:</span>
                                        <span class="telemetry-value">${{cp.telemetry.kw.toFixed(2)}} kW</span>
                                    </div>
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Energy:</span>
                                        <span class="telemetry-value">${{cp.telemetry.kwh.toFixed(3)}} kWh</span>
                                    </div>
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Cost:</span>
                                        <span class="telemetry-value">€${{cp.telemetry.euros.toFixed(4)}}</span>
                                    </div>
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Session:</span>
                                        <span class="telemetry-value">${{cp.telemetry.session_id || 'N/A'}}</span>
                                    </div>
                                `;
                            }} else {{
                                telemetryRows = `
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Power:</span>
                                        <span class="telemetry-value">N/A</span>
                                    </div>
                                `;
                            }}

                            // Add weather data from cache
                            let weatherHtml = '';
                            // First check if cp.weather is provided (from CP directly)
                            if (cp.weather && typeof cp.weather.temperature === 'number') {{
                                weatherHtml = `
                                    <div class="weather ${{cp.weather.alert ? 'weather-alert' : 'weather-ok'}}">
                                        City: ${{cp.city}}<br>
                                        ${{cp.weather.temperature.toFixed(1)}} °C<br>
                                        Status: ${{cp.weather.alert ? 'ALERT' : 'OK'}}
                                    </div>
                                `;
                            }} else if (cp.city && weatherCache[cp.city] && typeof weatherCache[cp.city].temperature === 'number') {{
                                // Then check weather cache
                                const w = weatherCache[cp.city];
                                const tempAlert = w.temperature > 35 || w.temperature < 0;
                                const cssClass = tempAlert ? 'weather-alert' : 'weather-ok';
                                weatherHtml = `
                                    <div class="weather ${{cssClass}}">
                                        🌡️ ${{cp.city}}: ${{w.temperature.toFixed(1)}}°C - ${{w.description || 'N/A'}}
                                    </div>
                                `;
                            }} else if (cp.city) {{
                                // Just show city name without "loading" message
                                weatherHtml = `<div class="weather">📍 ${{cp.city}}</div>`;
                            }}

                            const statusHtml = `
                                <div class="telemetry">
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Monitor:</span>
                                        <span class="telemetry-value">${{cp.monitor_status}}</span>
                                    </div>
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Engine:</span>
                                        <span class="telemetry-value">${{cp.engine_state}}</span>
                                    </div>
                                    <div class="telemetry-row">
                                        <span class="telemetry-label">Last Monitor Ping:</span>
                                        <span class="telemetry-value">${{formatTime(cp.monitor_last_seen)}}</span>
                                    </div>
                                    ${{telemetryRows}}
                                </div>
                            `;

                            const driverHtml = cp.current_driver ? 
                                `<div class="driver-info">👤 Driver: ${{cp.current_driver}}</div>` : '';
                            
                            const sessionHtml = cp.current_session ?
                                `<div class="driver-info">🔋 Session: ${{cp.current_session}}</div>` : '';
                            
                            const stopButtonHtml = cp.engine_state === 'SUPPLYING' ?
                                `<button class="stop-btn" onclick="stopCharging('${{cp.cp_id}}')">Stop Charging</button>`
                                : '';
                            
                            // Add encryption error warning if present
                            const encryptionWarningHtml = isEncryptionError ? `
                                <div class="encryption-warning">
                                    🔐 <strong>ENCRYPTION ERROR</strong><br>
                                    Key mismatch detected. Charging operations BLOCKED.<br>
                                    Error: ${{cp.encryption_error_type || 'Unknown'}}<br>
                                    <small>Verify encryption keys are synchronized.</small>
                                </div>
                            ` : '';
                            
                            // Determine display state for badge
                            const displayState = isEncryptionError ? 'ENCRYPTION_ERROR' : cp.state;
                            const displayStateText = isEncryptionError ? '🔐 ENCRYPTION ERROR' : cp.state;
                            
                            card.innerHTML = `
                                <div class="cp-header">
                                    <div class="cp-id">${{cp.cp_id}}</div>
                                    <span class="state-badge state-${{displayState}}">${{displayStateText}}</span>
                                </div>
                                ${{encryptionWarningHtml}}
                                ${{weatherHtml}}
                                ${{driverHtml}}
                                ${{sessionHtml}}
                                ${{statusHtml}}
                                ${{stopButtonHtml}}
                            `;
                            
                            cpGrid.appendChild(card);
                        }});
                        
                        // Update active requests list
                        updateActiveRequests(data.active_requests_details || []);
                        
                        // Update errors section - include system_events with ERROR severity
                        // Pass charging_points to filter out alerts for CPs that have recovered
                        updateErrors(data.system_errors || [], data.error_summary || {{}}, data.system_events || [], data.charging_points || []);
                        
                        // Update timestamp
                        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                    }} catch (error) {{
                        console.error('Error updating dashboard:', error);
                    }}
                }}
                
                function updateErrors(errors, summary, systemEvents, chargingPoints) {{
                    const container = document.getElementById('errors-list');
                    const section = document.getElementById('errors-section');
                    const summaryEl = document.getElementById('error-summary');
                    const errorCountEl = document.getElementById('error-count');
                    
                    if (!container || !section) return;
                    
                    // Build a set of CPs that currently have encryption errors
                    const cpsWithEncryptionError = new Set();
                    (chargingPoints || []).forEach(cp => {{
                        if (cp.communication_status === 'ENCRYPTION_ERROR') {{
                            cpsWithEncryptionError.add(cp.cp_id);
                        }}
                    }});
                    
                    // Only show security alerts for CPs that STILL have encryption errors
                    // This ensures alerts disappear when the key is fixed
                    const errorEvents = (systemEvents || [])
                        .filter(e => e.severity === 'ERROR' && e.type === 'SECURITY_ALERT')
                        .filter(e => cpsWithEncryptionError.has(e.component))  // Only show if CP still has error
                        .slice(0, 5)  // Limit to avoid duplicates
                        .map(e => ({{
                            message: e.message,
                            severity: 'CRITICAL',  // Promote security alerts to CRITICAL
                            source: 'SECURITY',
                            target: e.component,
                            timestamp: e.timestamp,
                            category: 'ENCRYPTION',
                            technical_detail: `Security event type: ${{e.type}}`,
                            resolved: false
                        }}));
                    
                    // Deduplicate by component - only show one alert per CP
                    const seenComponents = new Set();
                    const uniqueErrorEvents = errorEvents.filter(e => {{
                        if (seenComponents.has(e.target)) return false;
                        seenComponents.add(e.target);
                        return true;
                    }});
                    
                    const allErrors = [...(errors || []), ...uniqueErrorEvents];
                    const activeErrors = allErrors.filter(e => !e.resolved);
                    errorCountEl.textContent = activeErrors.length;
                    
                    if (activeErrors.length === 0) {{
                        section.classList.add('no-errors');
                        container.innerHTML = '<p style="color: #2e7d32; text-align: center;">✅ No active errors - All systems operational</p>';
                        summaryEl.style.display = 'none';
                        return;
                    }}
                    
                    section.classList.remove('no-errors');
                    summaryEl.style.display = 'flex';
                    
                    // Update summary
                    let summaryHtml = '';
                    const bySeverity = {{}};
                    activeErrors.forEach(e => {{
                        bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
                    }});
                    for (const [severity, count] of Object.entries(bySeverity)) {{
                        summaryHtml += `<div class="error-stat">${{severity}}: <span>${{count}}</span></div>`;
                    }}
                    summaryEl.innerHTML = summaryHtml;
                    
                    // Update error list
                    container.innerHTML = activeErrors.slice(0, 10).map(err => {{
                        const severityClass = err.severity.toLowerCase();
                        const badgeClass = err.severity === 'CRITICAL' ? 'critical' : 
                                          err.severity === 'ERROR' ? 'error' :
                                          err.severity === 'WARNING' ? 'warning' : 'info';
                        const icon = err.category === 'ENCRYPTION' ? '🔐' : '⚠️';
                        return `
                            <div class="error-item ${{severityClass}}">
                                <div class="error-content">
                                    <div class="error-message">${{icon}} ${{err.message}}</div>
                                    ${{err.technical_detail ? `<div class="error-detail">${{err.technical_detail}}</div>` : ''}}
                                    <div class="error-meta">
                                        <span class="error-badge ${{badgeClass}}">${{err.severity}}</span>
                                        <span>Source: ${{err.source}}</span>
                                        <span>Target: ${{err.target}}</span>
                                        <span>${{formatTime(err.timestamp)}}</span>
                                    </div>
                                </div>
                            </div>
                        `;
                    }}).join('');
                }}
                
                function updateActiveRequests(requests) {{
                    const container = document.getElementById('active-requests-list');
                    if (!container) return;
                    
                    if (requests.length === 0) {{
                        container.innerHTML = '<p style="color: #666; text-align: center;">No active requests</p>';
                        return;
                    }}
                    
                    container.innerHTML = requests.map(req => `
                        <div class="request-item">
                            <div class="request-info">
                                <strong>👤 ${{req.driver_id}}</strong>
                                <span>→ ${{req.cp_id}}</span>
                            </div>
                            <div class="request-meta">
                                <span class="request-id">ID: ${{req.request_id}}</span>
                                <span class="request-time">${{new Date(req.ts).toLocaleTimeString()}}</span>
                            </div>
                            <button class="stop-btn-small" onclick="stopCharging('${{req.cp_id}}')" title="End charging session">
                                ⏹️ End Session
                            </button>
                        </div>
                    `).join('');
                }}

                async function stopCharging(cp_id) {{
                    try {{
                        const response = await fetch('/cp/stop', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ cp_id }})
                        }});
                        const data = await response.json();
                        alert(data.message);
                        updateDashboard(); // refresh state after stopping
                    }} catch (error) {{
                        alert('Error stopping session: ' + error);
                        console.error(error);
                    }}
                }}
                
                function refresh() {{
                    updateDashboard();
                }}
                
                // Initial load - fetch weather first, then start dashboard updates
                // Wrapped in error handling to ensure dashboard continues even if weather fails
                (async function() {{
                    try {{
                        await updateWeather(); // Load weather data first (fault-tolerant)
                        lastWeatherFetch = Date.now(); // Reset timer after initial fetch
                    }} catch (e) {{
                        console.warn('Initial weather fetch failed, continuing without weather:', e.message);
                    }}
                    
                    try {{
                        await updateDashboard(); // Then render with weather data (if available)
                    }} catch (e) {{
                        console.error('Initial dashboard update failed:', e.message);
                    }}
                    
                    // Auto-refresh every 1 second for real-time updates
                    // Each update is fault-tolerant and will not crash the page
                    setInterval(() => {{
                        try {{
                            updateDashboard();
                        }} catch (e) {{
                            console.error('Dashboard update error:', e.message);
                        }}
                    }}, 1000);
                }})();
            </script>
        </head>
        <body>
            <div class="container">
                <h1>⚡ EV Central Dashboard <span style="font-size: 0.5em; color: #999;">Last update: <span id="last-update">--:--:--</span></span></h1>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value" id="total-cps">{len(data['charging_points'])}</div>
                        <div class="stat-label">Total Charging Points</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="active-requests">{data['active_requests']}</div>
                        <div class="stat-label">Active Requests</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="currently-charging">{sum(1 for cp in data['charging_points'] if cp['engine_state'] == 'SUPPLYING')}</div>
                        <div class="stat-label">Currently Charging</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="error-count">{data.get('error_summary', {}).get('total_active', 0)}</div>
                        <div class="stat-label">Active Errors</div>
                    </div>
                </div>
                
                <!-- System Errors Section -->
                <div class="errors-section {'no-errors' if not data.get('system_errors') else ''}" id="errors-section">
                    <h2>🚨 System Errors & Alerts</h2>
                    <div class="error-summary" id="error-summary" style="{'display: none;' if not data.get('system_errors') else ''}">
                    </div>
                    <div id="errors-list">
                        {'<p style="color: #2e7d32; text-align: center;">✅ No active errors - All systems operational</p>' if not data.get('system_errors') else ''}
                    </div>
                </div>
                
                <!-- Active Sessions Section -->
                <div class="active-sessions">
                    <h2>🔋 Active Charging Sessions</h2>
                    <div id="active-requests-list">
                        <p style="color: #666; text-align: center;">No active requests</p>
                    </div>
                </div>
                
                <h2>Charging Points</h2>
                <div class="cp-grid" id="cp-grid">
            """
        
        for cp in data['charging_points']:
            telemetry_rows = ""
            if cp.get('telemetry'):
                t = cp['telemetry']
                telemetry_rows = f"""
                    <div class="telemetry-row">
                        <span class="telemetry-label">Power:</span>
                        <span class="telemetry-value">{t['kw']:.2f} kW</span>
                    </div>
                    <div class="telemetry-row">
                        <span class="telemetry-label">Energy:</span>
                        <span class="telemetry-value">{t['kwh']:.3f} kWh</span>
                    </div>
                    <div class="telemetry-row">
                        <span class="telemetry-label">Cost:</span>
                        <span class="telemetry-value">€{t['euros']:.2f}</span>
                    </div>
                    <div class="telemetry-row">
                        <span class="telemetry-label">Session:</span>
                        <span class="telemetry-value">{t.get('session_id', 'N/A')}</span>
                    </div>
                """
            else:
                telemetry_rows = """
                    <div class="telemetry-row">
                        <span class="telemetry-label">Power:</span>
                        <span class="telemetry-value">N/A</span>
                    </div>
                """

            weather_html = "<div class='weather'> Weather: Unknown</div>"

            weather = cp.get("weather")
            if weather:
                css_class = "weather-alert" if weather["alert"] else "weather-ok"
                weather_html = f"""
                    <div class="weather {css_class}">
                        City: {cp.get('city', 'Unknown')}<br>
                        {weather['temperature']:.1f} °C<br>
                        Status: {'ALERT' if weather['alert'] else 'OK'}
                    </div>
                """

            status_html = f"""
                <div class="telemetry">
                    <div class="telemetry-row">
                        <span class="telemetry-label">Monitor:</span>
                        <span class="telemetry-value">{cp['monitor_status']}</span>
                    </div>
                    <div class="telemetry-row">
                        <span class="telemetry-label">Engine:</span>
                        <span class="telemetry-value">{cp['engine_state']}</span>
                    </div>
                    <div class="telemetry-row">
                        <span class="telemetry-label">Last Monitor Ping:</span>
                        <span class="telemetry-value">{cp.get('monitor_last_seen', 'Unknown')}</span>
                    </div>
                    {telemetry_rows}
                </div>
            """

            stop_button = ""
            if (cp["engine_state"]) == "SUPPLYING":
                logger.debug(f"The engine supplies: {cp['cp_id']}")
                stop_button = f"""
                <button class="stop-btn" onclick="stopCharging('{cp['cp_id']}')">Stop Charging</button>
                """
            driver_html = f'<div class="driver-info">👤 Driver: {cp["current_driver"]}</div>' if cp.get('current_driver') else ''
            
            html_content += f"""
                    <div class="cp-card">
                        <div class="cp-header">
                            <div class="cp-id">{cp['cp_id']}</div>
                            <span class="state-badge state-{cp['state']}">{cp['state']}</span>
                        </div>
                        {weather_html}
                        {driver_html}
                        {status_html}
                        {stop_button}
                    </div>
            """
        
        html_content += """
                </div>
                
                <button class="refresh-btn" onclick="refresh()">🔄 Refresh Now</button>
            </div>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)
    
    return app
