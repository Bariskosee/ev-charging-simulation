"""
EV Driver - Driver client for requesting charging sessions.

Responsibilities:
- Read CP IDs from file or use defaults
- Send charging requests to Central via Kafka
- Wait for status updates and display progress
- Handle multiple sequential requests
"""

import asyncio
import argparse
import sys
import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from loguru import logger
from uvicorn import Config, Server

from evcharging.common.config import DriverConfig, TOPICS
from evcharging.common.kafka import KafkaProducerHelper, KafkaConsumerHelper, ensure_topics
from evcharging.common.messages import DriverRequest, DriverUpdate, MessageStatus, CPSessionTicket
from evcharging.common.utils import generate_id, utc_now
from evcharging.common.charging_points import get_metadata
from evcharging.common.error_manager import (
    ErrorManager, ErrorCategory, ErrorSeverity, ErrorSource,
    get_error_manager, report_connection_error, report_communication_error,
    resolve_target_errors
)
from evcharging.apps.ev_driver.dashboard import (
    create_driver_dashboard_app,
    ChargingPointDetail,
    SessionSummary,
    SessionHistoryEntry,
    Notification,
    BroadcastAlert,
    Location,
)


class EVDriver:
    """Driver client for requesting charging sessions."""
    
    def __init__(self, config: DriverConfig):
        self.config = config
        self.driver_id = config.driver_id
        self.producer: KafkaProducerHelper | None = None
        self.consumer: KafkaConsumerHelper | None = None
        self.pending_requests: dict[str, DriverRequest] = {}
        self.completed_requests: list[str] = []
        self.session_state: Dict[str, SessionSummary] = {}
        self.session_history: List[SessionHistoryEntry] = []
        self.notifications: List[Notification] = []
        self.alerts: List[BroadcastAlert] = []
        self.favorites: set[str] = set()
        self.charging_points: Dict[str, ChargingPointDetail] = {}
        self._state_lock = asyncio.Lock()
        self._poll_task: Optional[asyncio.Task] = None
        self._dashboard_task: Optional[asyncio.Task] = None
        self._running = False
        self.central_https_url = config.central_https_url.rstrip("/")
        self.dashboard_port = config.dashboard_port
        self.ticket_file = f"driver_tickets/driver_{self.driver_id}_tickets.txt"
        
        # Sync status tracking for fault isolation visibility
        self._last_central_sync: Optional[datetime] = None
        self._central_connected: bool = False
        self._central_error: Optional[str] = None
        self._consecutive_failures: int = 0
        self._was_previously_connected: bool = False  # Track if we were ever connected
        
        # Initialize error manager for centralized error tracking
        self.error_manager = get_error_manager()
    
    async def start(self):
        """Initialize and start the driver client."""
        logger.info(f"Starting Driver client: {self.driver_id}")
        
        # Ensure Kafka topics exist
        await ensure_topics(
            self.config.kafka_bootstrap,
            list(TOPICS.values())
        )
        
        # Initialize Kafka producer
        self.producer = KafkaProducerHelper(self.config.kafka_bootstrap)
        await self.producer.start()
        
        # Initialize Kafka consumer for updates
        self.consumer = KafkaConsumerHelper(
            self.config.kafka_bootstrap,
            topics=[TOPICS["DRIVER_UPDATES"], TOPICS["TICKET_TO_DRIVER"]],
            group_id=f"driver-{self.driver_id}",
            auto_offset_reset="latest"
        )
        await self.consumer.start()

        await self.load_saved_tickets();
        
        logger.info(f"Driver {self.driver_id} started successfully")
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_central_loop(), name="driver-poll-central")
    
    async def stop(self):
        """Stop the driver client gracefully."""
        logger.info(f"Stopping Driver: {self.driver_id}")
        self._running = False
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        
        logger.info(f"Driver {self.driver_id} stopped")
    
    def load_cp_ids(self) -> list[str]:
        """Load CP IDs from file or return defaults."""
        if self.config.requests_file:
            try:
                path = Path(self.config.requests_file)
                if path.exists():
                    cp_ids = [
                        line.strip()
                        for line in path.read_text().splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
                    logger.info(f"Loaded {len(cp_ids)} CP IDs from {self.config.requests_file}")
                    return cp_ids
                else:
                    logger.warning(f"Requests file not found: {self.config.requests_file}")
            except Exception as e:
                logger.error(f"Error loading requests file: {e}")
        
        # Default CP IDs if no file
        default_cps = ["CP-001", "CP-002", "CP-001"]
        logger.info(f"Using default CP IDs: {default_cps}")
        return default_cps
    
    async def send_request(self, cp_id: str) -> DriverRequest:
        """Send a charging request for a specific CP."""
        request_id = generate_id("req")
        
        request = DriverRequest(
            request_id=request_id,
            driver_id=self.driver_id,
            cp_id=cp_id,
            ts=utc_now()
        )
        
        self.pending_requests[request_id] = request
        
        await self.producer.send(TOPICS["DRIVER_REQUESTS"], request, key=self.driver_id)
        
        logger.info(
            f"📤 Driver {self.driver_id} requested charging at {cp_id} "
            f"(request_id: {request_id})"
        )
        
        await self._record_request_state(
            SessionSummary(
                session_id="pending-" + request_id,
                request_id=request_id,
                cp_id=cp_id,
                status="PENDING",
                queue_position=None,
            )
        )
        
        return request
    
    async def handle_update(self, update: DriverUpdate):
        """Process status update from Central."""
        request_id = update.request_id
        
        # Check if this is our request (either in pending_requests or session_state)
        is_our_request = request_id in self.pending_requests
        async with self._state_lock:
            is_in_session_state = request_id in self.session_state
        
        if not is_our_request and not is_in_session_state:
            logger.debug(f"Ignoring update for unknown request: {request_id}")
            return  # Not our request
        
        status_emoji = {
            MessageStatus.ACCEPTED: "✅",
            MessageStatus.DENIED: "❌",
            MessageStatus.IN_PROGRESS: "🔋",
            MessageStatus.COMPLETED: "✔️",
            MessageStatus.FAILED: "⚠️",
        }.get(update.status, "ℹ️")
        
        logger.info(
            f"{status_emoji} Driver {self.driver_id} | {update.cp_id} | "
            f"{update.status.value.upper()} | {update.reason or 'No details'}"
        )
        
        await self._apply_status_update(update)
        
        # Mark as completed if terminal state
        if update.status in {MessageStatus.COMPLETED, MessageStatus.DENIED, MessageStatus.FAILED}:
            self.completed_requests.append(request_id)
            if request_id in self.pending_requests:
                del self.pending_requests[request_id]
        
    async def handle_ticket(self, ticket: CPSessionTicket):
        """Persist the ticket locally and handle logic."""
        if ticket.driver_id != self.driver_id:
            return
    
        if not hasattr(self, "saved_tickets"):
            self.saved_tickets = []
        self.saved_tickets.append(ticket)

        try:
            logger.info(f"Received ticket for driver {self.driver_id}: {ticket}")
            os.makedirs("driver_tickets", exist_ok=True)
            with open(self.ticket_file, "a", encoding="utf-8") as f:
                f.write(ticket.model_dump_json() + "\n")

            logger.info(f"Ticket saved to {self.ticket_file}")
        except Exception as e:
            logger.error(f"Failed to write ticket: {e}")
    
    async def process_messages(self):
        """Listen for all Kafka messages (updates and tickets) from Central."""
        async for msg in self.consumer.consume():
            try:
                topic = msg["topic"]
                value = msg["value"]
                
                if topic == TOPICS["DRIVER_UPDATES"]:
                    update = DriverUpdate(**value)
                    
                    # Filter by driver ID
                    if update.driver_id == self.driver_id:
                        logger.info(f"Received update for driver {self.driver_id}: {update.status.value}")
                        await self.handle_update(update)
                
                elif topic == TOPICS["TICKET_TO_DRIVER"]:
                    ticket = CPSessionTicket(**value)
                                        
                    # Filter by driver ID
                    if ticket.driver_id == self.driver_id:
                        logger.info(f"=== DRIVER {self.driver_id} received ticket for session {ticket.session_id}")
                        await self.handle_ticket(ticket)
            
            except Exception as e:
                logger.error(f"Error processing message from {msg.get('topic', 'unknown')}: {e}")
    
    async def load_saved_tickets(self):
        """Load previously saved tickets from file on driver restart."""
        self.saved_tickets = []

        try:
            with open(self.ticket_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        self.saved_tickets.append(CPSessionTicket(**data))
                    except Exception as e:
                        logger.warning(f"Could not parse ticket line: {line} ({e})")

            logger.info(f"Loaded {len(self.saved_tickets)} saved tickets")
        except FileNotFoundError:
            logger.info("No saved tickets file found — starting clean.")

    
    async def run_requests(self):
        """Execute charging requests from file."""
        cp_ids = self.load_cp_ids()
        
        if not cp_ids:
            logger.warning("No CP IDs to request")
            return
        
        for i, cp_id in enumerate(cp_ids, 1):
            logger.info(f"--- Request {i}/{len(cp_ids)} ---")
            
            # Send request
            request = await self.send_request(cp_id)
            
            # Wait for completion (or timeout)
            timeout = 30  # 30 seconds per request
            start_time = asyncio.get_event_loop().time()
            
            while request.request_id in self.pending_requests:
                await asyncio.sleep(0.5)
                
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed > timeout:
                    logger.warning(f"Request {request.request_id} timed out after {timeout}s")
                    if request.request_id in self.pending_requests:
                        del self.pending_requests[request.request_id]
                    break
            
            # Wait between requests
            if i < len(cp_ids):
                logger.info(f"Waiting {self.config.request_interval}s before next request...")
                await asyncio.sleep(self.config.request_interval)
        
        logger.info(f"✨ All requests completed. Total: {len(self.completed_requests)}/{len(cp_ids)}")
    
    # ------------------------------------------------------------------
    # Dashboard state helpers
    # ------------------------------------------------------------------

    async def _poll_central_loop(self):
        """Poll EV Central dashboard endpoint to keep CP state fresh.
        
        Note: This only affects dashboard display. Core charging operations
        continue via Kafka even if Central's HTTP API is unavailable.
        """
        logger.info("Driver: starting central polling loop")
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            while self._running:
                try:
                    resp = await client.get(f"{self.central_https_url}/cp")
                    resp.raise_for_status()
                    payload = resp.json()
                    await self._update_charging_points(payload.get("charging_points", []))
                    
                    # Check if this is a restoration (was disconnected, now connected)
                    was_disconnected = self._was_previously_connected and not self._central_connected
                    
                    # Update sync status on success
                    self._last_central_sync = utc_now()
                    self._central_connected = True
                    self._central_error = None
                    
                    # Generate restoration notification if recovering from failure
                    if was_disconnected:
                        logger.info(
                            f"Driver: Central dashboard RESTORED after {self._consecutive_failures} failures. "
                            "Full functionality resumed."
                        )
                        # Add user-visible notification
                        async with self._state_lock:
                            self.notifications.append(
                                Notification(
                                    notification_id=generate_id("note"),
                                    created_at=utc_now(),
                                    message="✅ Central dashboard connection restored. All services operational.",
                                    type="ALERT",
                                    read=False,
                                )
                            )
                    
                    self._consecutive_failures = 0
                    self._was_previously_connected = True
                    
                    # Resolve any previous Central connection errors
                    resolve_target_errors("Central", "Central dashboard connection restored")
                    
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._consecutive_failures += 1
                    self._central_connected = False
                    self._central_error = str(exc)
                    
                    # Log warning only on first failure or every 10th failure
                    if self._consecutive_failures == 1:
                        logger.warning(
                            f"Driver: Central {self.central_https_url} dashboard unreachable - {exc}. "
                            "CP status display may be stale. Charging operations continue via Kafka."
                        )
                        # Report error to error manager for display
                        report_connection_error(
                            source=ErrorSource.DRIVER,
                            target="Central",
                            service_name="Central dashboard",
                            detail=str(exc)
                        )
                        # Add user-visible notification for first failure
                        if self._was_previously_connected:
                            async with self._state_lock:
                                self.notifications.append(
                                    Notification(
                                        notification_id=generate_id("note"),
                                        created_at=utc_now(),
                                        message="⚠️ Central dashboard temporarily unavailable. Charging operations continue normally.",
                                        type="ALERT",
                                        read=False,
                                    )
                                )
                    elif self._consecutive_failures % 10 == 0:
                        logger.debug(f"Driver: Central {self.central_https_url} still unreachable ({self._consecutive_failures} failures)")
                        
                await asyncio.sleep(1.5)
        logger.info("Driver: central polling loop stopped")

    async def _update_charging_points(self, central_points: List[dict]):
        async with self._state_lock:
            # Get set of current CP IDs from Central
            central_cp_ids = {item["cp_id"] for item in central_points}
            
            # Remove CPs that are no longer in Central
            removed_cps = [cp_id for cp_id in self.charging_points if cp_id not in central_cp_ids]
            for cp_id in removed_cps:
                del self.charging_points[cp_id]
                logger.info(f"Removed CP {cp_id} from local cache (no longer in Central)")
            
            for item in central_points:
                cp_id = item["cp_id"]
                meta = get_metadata(cp_id)
                
                # If metadata not available, create basic info from Central data
                if not meta:
                    # Use city from Central's data
                    city = item.get("city", "Unknown")
                    status = self._map_engine_status(item)
                    telemetry = item.get("telemetry") or {}
                    
                    detail = ChargingPointDetail(
                        cp_id=cp_id,
                        name=f"CP {cp_id}",  # Generic name
                        status=status,
                        power_kw=22.0,  # Default power
                        connector_type="Type 2",  # Default connector
                        location=Location(
                            address=city,
                            city=city,
                            latitude=0.0,
                            longitude=0.0,
                            distance_km=None,
                        ),
                        queue_length=1 if status == "OCCUPIED" else 0,
                        estimated_wait_minutes=15 if status == "OCCUPIED" else 0,
                        favorite=cp_id in self.favorites,
                        amenities=[],
                        price_eur_per_kwh=0.30,
                        last_updated=utc_now(),
                    )
                    self.charging_points[cp_id] = detail
                    continue
                
                # Use metadata if available
                status = self._map_engine_status(item)
                telemetry = item.get("telemetry") or {}
                detail = ChargingPointDetail(
                    cp_id=cp_id,
                    name=meta.name,
                    status=status,
                    power_kw=meta.power_kw,
                    connector_type=meta.connector_type,
                    location=Location(
                        address=meta.address,
                        city=meta.city,
                        latitude=meta.latitude,
                        longitude=meta.longitude,
                        distance_km=None,
                    ),
                    queue_length=1 if status == "OCCUPIED" else 0,
                    estimated_wait_minutes=15 if status == "OCCUPIED" else 0,
                    favorite=cp_id in self.favorites,
                    amenities=meta.amenities,
                    price_eur_per_kwh=0.30 if meta.connector_type == "Type 2" else 0.42,
                    last_updated=utc_now(),
                )
                # Inject telemetry into detail if present
                if telemetry:
                    detail.estimated_wait_minutes = 0 if status != "OCCUPIED" else max(
                        detail.estimated_wait_minutes,
                        10
                    )
                self.charging_points[cp_id] = detail

                energy = telemetry.get("kwh") if telemetry else None
                cost = telemetry.get("euros") if telemetry else None

                for req_id, summary in list(self.session_state.items()):
                    if summary.cp_id == cp_id and summary.status == "CHARGING":
                        self.session_state[req_id] = summary.model_copy(
                            update={
                                "energy_kwh": energy,
                                "cost_eur": cost,
                            }
                        )

                if status == "OFFLINE":
                    for summary in self.session_state.values():
                        if summary.cp_id == cp_id and summary.status in {"PENDING", "APPROVED"}:
                            note = Notification(
                                notification_id=generate_id("note"),
                                created_at=utc_now(),
                                message=f"Charging point {cp_id} is currently offline.",
                                type="ALERT",
                                read=False,
                            )
                            self.notifications.append(note)

    def _map_engine_status(self, point: dict) -> str:
        state = point.get("engine_state")
        display_state = point.get("state")
        current_driver = point.get("current_driver")
        communication_status = point.get("communication_status", "OK")
        
        # CRITICAL: Check for encryption error first
        if display_state == "ENCRYPTION_ERROR" or communication_status == "ENCRYPTION_ERROR":
            return "ENCRYPTION_ERROR"
        
        if display_state == "TURNED_OFF_WEATHER":
            return "OFFLINE"
        if display_state == "DISCONNECTED":
            return "OFFLINE"
        if display_state == "BROKEN":
            return "OFFLINE"
        if state == "SUPPLYING" or current_driver:
            return "OCCUPIED"
        return "FREE"

    async def _record_request_state(self, summary: SessionSummary):
        async with self._state_lock:
            self.session_state[summary.request_id] = summary

    async def _apply_status_update(self, update: DriverUpdate):
        status_map = {
            MessageStatus.ACCEPTED: "APPROVED",
            MessageStatus.IN_PROGRESS: "CHARGING",
            MessageStatus.COMPLETED: "COMPLETED",
            MessageStatus.DENIED: "DENIED",
            MessageStatus.FAILED: "FAILED",
        }
        new_status = status_map.get(update.status, "PENDING")
        async with self._state_lock:
            current = self.session_state.get(update.request_id)
            if not current:
                current = SessionSummary(
                    session_id=update.session_id or generate_id("session"),
                    request_id=update.request_id,
                    cp_id=update.cp_id,
                    status=new_status,
                )
            updated = current.model_copy(
                update={
                    "session_id": update.session_id or current.session_id,  # Update session_id from Central
                    "status": new_status,
                    "started_at": current.started_at or (utc_now() if new_status == "CHARGING" else None),
                    "completed_at": utc_now() if new_status in {"COMPLETED", "DENIED", "FAILED"} else None,
                }
            )
            self.session_state[update.request_id] = updated

            note = Notification(
                notification_id=generate_id("note"),
                created_at=utc_now(),
                message=update.reason or f"Session {new_status.lower()} for {update.cp_id}",
                type="SESSION",
                read=False,
            )
            self.notifications.append(note)

            if new_status in {"COMPLETED", "DENIED", "FAILED"}:
                history_entry = SessionHistoryEntry(
                    **updated.model_dump(),
                    receipt_url=None,
                )
                self.session_history.append(history_entry)

    # ------------------------------------------------------------------
    # Dashboard-facing getters
    # ------------------------------------------------------------------

    async def dashboard_charging_points(self, **filters) -> List[ChargingPointDetail]:
        async with self._state_lock:
            points = list(self.charging_points.values())
        city = filters.get("city")
        connector_type = filters.get("connector_type")
        min_power_kw = filters.get("min_power_kw")
        only_available = filters.get("only_available")
        if city:
            points = [p for p in points if p.location.city.lower() == city.lower()]
        if connector_type:
            points = [p for p in points if p.connector_type.lower() == connector_type.lower()]
        if min_power_kw is not None:
            points = [p for p in points if p.power_kw >= min_power_kw]
        if only_available:
            points = [p for p in points if p.status == "FREE"]
        return points

    async def dashboard_charging_point(self, cp_id: str) -> ChargingPointDetail:
        async with self._state_lock:
            cp = self.charging_points.get(cp_id)
        if not cp:
            meta = get_metadata(cp_id)
            if not meta:
                raise KeyError(cp_id)
            cp = ChargingPointDetail(
                cp_id=cp_id,
                name=meta.name,
                status="OFFLINE",
                power_kw=meta.power_kw,
                connector_type=meta.connector_type,
                location=Location(
                    address=meta.address,
                    city=meta.city,
                    latitude=meta.latitude,
                    longitude=meta.longitude,
                    distance_km=None,
                ),
                queue_length=0,
                estimated_wait_minutes=0,
                favorite=cp_id in self.favorites,
                amenities=meta.amenities,
                price_eur_per_kwh=0.30 if meta.connector_type == "Type 2" else 0.42,
                last_updated=utc_now(),
            )
        return cp

    async def dashboard_current_session(self) -> Optional[SessionSummary]:
        async with self._state_lock:
            active = [
                s for s in self.session_state.values()
                if s.status in {"PENDING", "APPROVED", "CHARGING"}
            ]
        return active[0] if active else None

    async def dashboard_session_history(self) -> List[SessionHistoryEntry]:
        async with self._state_lock:
            return list(self.session_history)

    async def dashboard_notifications(self) -> List[Notification]:
        async with self._state_lock:
            return list(self.notifications)

    async def dashboard_alerts(self) -> List[BroadcastAlert]:
        async with self._state_lock:
            return list(self.alerts)

    async def dashboard_favorites(self) -> List[ChargingPointDetail]:
        async with self._state_lock:
            return [cp for cp in self.charging_points.values() if cp.cp_id in self.favorites]

    async def dashboard_add_favorite(self, cp_id: str):
        self.favorites.add(cp_id)

    async def dashboard_remove_favorite(self, cp_id: str):
        self.favorites.discard(cp_id)

    async def dashboard_request_summary(self, request_id: str) -> SessionSummary:
        async with self._state_lock:
            summary = self.session_state.get(request_id)
        if not summary:
            raise KeyError(request_id)
        return summary

    async def dashboard_cancel_request(self, request_id: str) -> bool:
        async with self._state_lock:
            summary = self.session_state.get(request_id)
            if not summary or summary.status not in {"PENDING", "APPROVED"}:
                return False
            cancelled = summary.model_copy(update={"status": "CANCELLED", "completed_at": utc_now()})
            self.session_state[request_id] = cancelled
            self.pending_requests.pop(request_id, None)
            self.notifications.append(
                Notification(
                    notification_id=generate_id("note"),
                    created_at=utc_now(),
                    message=f"Request {request_id} cancelled.",
                    type="SESSION",
                    read=False,
                )
            )
            self.session_history.append(SessionHistoryEntry(**cancelled.model_dump(), receipt_url=None))
            return True

    def get_errors(self) -> dict:
        """Get current system errors for dashboard display."""
        return {
            "errors": self.error_manager.get_errors_for_display(
                source=ErrorSource.DRIVER,
                limit=20
            ),
            "summary": self.error_manager.get_error_summary(),
            "all_errors": self.error_manager.get_errors_for_display(limit=30),
        }

    def get_sync_status(self) -> dict:
        """Get Central dashboard sync status for fault isolation visibility.
        
        Returns status information about the connection to Central's HTTP API.
        Note: Even if Central dashboard is down, charging operations continue via Kafka.
        """
        # Calculate staleness
        stale_threshold_seconds = 10  # Data is "stale" if older than 10 seconds
        
        if self._last_central_sync:
            age_seconds = (utc_now() - self._last_central_sync).total_seconds()
            is_stale = age_seconds > stale_threshold_seconds
        else:
            age_seconds = None
            is_stale = True
        
        return {
            "central_connected": self._central_connected,
            "last_sync": self._last_central_sync.isoformat() if self._last_central_sync else None,
            "age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
            "is_stale": is_stale,
            "error": self._central_error,
            "consecutive_failures": self._consecutive_failures,
            # Remind users that core operations are unaffected
            "kafka_operational": True,  # Kafka is separate from HTTP polling
            "charging_operations_affected": False,  # Only display is affected
        }

    async def dashboard_stop_session(self, session_id: str) -> Optional[SessionSummary]:
        """Request to stop an active charging session via Central."""
        async with self._state_lock:
            # Find the session
            for req_id, summary in self.session_state.items():
                if summary.session_id == session_id:
                    if summary.status not in {"CHARGING", "APPROVED"}:
                        logger.warning(f"Cannot stop session {session_id} - not in active state (status: {summary.status})")
                        return None
                    
                    # Send stop request to Central via HTTP
                    try:
                        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                            response = await client.post(
                                f"{self.central_https_url}/stop-session",
                                json={
                                    "cp_id": summary.cp_id,
                                    "driver_id": self.driver_id,
                                    "session_id": session_id
                                }
                            )
                            response.raise_for_status()
                            logger.info(f"Stop session request sent to Central for {session_id}")
                    except Exception as e:
                        logger.error(f"Failed to send stop session request to Central: {e}")
                        return None
                    
                    # Don't update local state to STOPPED immediately
                    # Wait for COMPLETED update from Central via Kafka
                    # This prevents the session from appearing to restart
                    self.notifications.append(
                        Notification(
                            notification_id=generate_id("note"),
                            created_at=utc_now(),
                            message=f"Session {session_id} stop requested, waiting for confirmation...",
                            type="SESSION",
                            read=False,
                        )
                    )
                    return summary
        return None


async def main():
    """Main entry point for Driver client."""
    parser = argparse.ArgumentParser(description="EV Driver Client")
    parser.add_argument("--driver-id", type=str, help="Driver identifier")
    parser.add_argument("--kafka-bootstrap", type=str, help="Kafka bootstrap servers")
    parser.add_argument("--requests-file", type=str, help="File with CP IDs to request")
    parser.add_argument("--request-interval", type=float, help="Interval between requests (seconds)")
    parser.add_argument("--log-level", type=str, help="Log level")
    parser.add_argument("--central-https-url", type=str, help="URL to connect to the Central")
    
    args = parser.parse_args()
    
    # Build config from args (only non-None values), env vars will fill the rest
    config_dict = {k: v for k, v in vars(args).items() if v is not None and k != 'log_level'}
    config = DriverConfig(**config_dict)
    
    # Use log level from args or config
    log_level = args.log_level if args.log_level else config.log_level
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <magenta>Driver:{extra[driver_id]}</magenta> | <level>{message}</level>",
        level=log_level
    )
    logger.configure(extra={"driver_id": config.driver_id})
    
    # Initialize driver
    driver = EVDriver(config)
    
    message_task: Optional[asyncio.Task] = None
    dashboard_task: Optional[asyncio.Task] = None

    try:
        await driver.start()

        # Start unified message listener for updates and tickets
        message_task = asyncio.create_task(driver.process_messages(), name="driver-message-listener")

        # Start dashboard HTTP server
        dashboard_app = create_driver_dashboard_app(driver)
        dashboard_config = Config(
            dashboard_app,
            host="0.0.0.0",
            port=driver.dashboard_port,
            log_level=log_level.lower(),
        )
        dashboard_server = Server(dashboard_config)
        dashboard_task = asyncio.create_task(dashboard_server.serve(), name="driver-dashboard-server")

        logger.info(f"Driver dashboard available at http://localhost:{driver.dashboard_port}")

        driver._dashboard_task = dashboard_task

        # Run scripted requests only if auto_run_requests is enabled
        if driver.config.auto_run_requests:
            logger.info("Auto-running scripted requests (auto_run_requests=True)")
            await driver.run_requests()
        else:
            logger.info("Manual mode: Use the dashboard to start charging sessions")

        # Keep service alive to serve dashboard / notifications
        await asyncio.Future()
    
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        for task in (message_task, dashboard_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        await driver.stop()


if __name__ == "__main__":
    asyncio.run(main())
