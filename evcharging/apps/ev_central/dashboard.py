"""
Dashboard for EV Central - FastAPI web interface.
Provides real-time view of charging points and telemetry.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import TYPE_CHECKING
from loguru import logger

from evcharging.common.messages import CPRegistration, WeatherReport

if TYPE_CHECKING:
    from evcharging.apps.ev_central.main import EVCentralController


def create_dashboard_app(controller: "EVCentralController") -> FastAPI:
    """Create FastAPI application for dashboard."""
    
    app = FastAPI(title="EV Central Dashboard", version="0.1.0")
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "service": "ev-central"}
    
    @app.post("/cp/register")
    async def register_cp(registration: CPRegistration):
        """Register or update a charging point."""
        success = controller.register_cp(registration)
        return {
            "success": success,
            "cp_id": registration.cp_id,
            "message": "Charging point registered successfully" if success else "Registration failed"
        }
    
    @app.post("/cp/fault")
    async def notify_fault(fault_data: dict):
        """Receive fault/health notifications from CP monitors."""
        cp_id = fault_data.get("cp_id")
        status = fault_data.get("status")
        reason = fault_data.get("reason", "")
        
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
    async def monitor_heartbeat(payload: dict):
        """Receive heartbeat ping from CP Monitor."""
        cp_id = payload.get("cp_id")
        if not cp_id:
            raise HTTPException(status_code=400, detail="cp_id required")

        controller.record_monitor_ping(cp_id)
        return {"success": True, "cp_id": cp_id}
    
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
            "active_requests": data["active_requests"]
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

    @app.post("/weather/report")
    async def receive_weather_report(data: WeatherReport):
        city = data.city
        temperature = data.temperature
        weather_status = []
        
        weather_status = weather_status.append({
                    "city": city,
                    "temperature": temperature,
                })
        
        return {"success": True, "city": city}

    @app.post("/weather/alert")
    async def receive_alert(data: WeatherReport):
        city = data.city
        temperature = data.temperature
        alert = data.alert
        
        if (alert):
            pass
            # TODO invoke method to shut down the cp in the given city
        
        return {"success": True, "city": city, "temperature": temperature, "alert": alert}

    @app.post("/weather/cancel_alert")
    async def receive_alert_cancel(data: WeatherReport):
        city = data.city
        temperature = data.temperature
        alert = data.alert

        if (not alert):
            pass
            # TODO invoke method to clear the fault in the cp in the given city
        
        return {"success": True, "city": city, "temperature": temperature, "alert": alert}
    
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
                }}
                .stat-card {{
                    flex: 1;
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
            </style>
            <script>
                // Fetch and update data without page reload
                function formatTime(ts) {{
                    if (!ts) return 'Unknown';
                    const date = new Date(ts);
                    return date.toLocaleTimeString();
                }}

                async function updateDashboard() {{
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
                            card.className = 'cp-card';
                            
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
                            
                            const stopButtonHtml = cp.engine_state === 'SUPPLYING' ?
                                `<button class="stop-btn" onclick="stopCharging('${{cp.cp_id}}')">Stop Charging</button>`
                                : '';
                            
                            card.innerHTML = `
                                <div class="cp-header">
                                    <div class="cp-id">${{cp.cp_id}}</div>
                                    <span class="state-badge state-${{cp.state}}">${{cp.state}}</span>
                                </div>
                                ${{driverHtml}}
                                ${{statusHtml}}
                                ${{stopButtonHtml}}
                            `;
                            
                            cpGrid.appendChild(card);
                        }});
                        
                        // Update timestamp
                        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                    }} catch (error) {{
                        console.error('Error updating dashboard:', error);
                    }}
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
                
                // Initial load
                updateDashboard();
                
                // Auto-refresh every 1 second for real-time updates
                setInterval(updateDashboard, 1000);
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
