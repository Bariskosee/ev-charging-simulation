"""
Database persistence layer for fault history and events.
Uses SQLite for simplicity and portability.
"""

import sqlite3
from datetime import datetime
from typing import List, Optional, Dict
from contextlib import contextmanager
from pathlib import Path

from evcharging.common.utils import utc_now


class FaultHistoryDB:
    """Database manager for fault history and events."""
    
    def __init__(self, db_path: str = "ev_charging.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Fault events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fault_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cp_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,  -- 'FAULT' or 'RECOVERY'
                    reason TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # CP health history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cp_health_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cp_id TEXT NOT NULL,
                    is_healthy BOOLEAN NOT NULL,
                    state TEXT,
                    circuit_state TEXT,
                    failure_count INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Charging sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS charging_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL UNIQUE,
                    cp_id TEXT NOT NULL,
                    driver_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    total_kwh REAL,
                    total_cost REAL,
                    status TEXT,  -- 'ACTIVE', 'COMPLETED', 'FAILED'
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_fault_events_cp_id 
                ON fault_events(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_fault_events_timestamp 
                ON fault_events(timestamp)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_health_history_cp_id 
                ON cp_health_history(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_cp_id 
                ON charging_sessions(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_driver_id 
                ON charging_sessions(driver_id)
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
        finally:
            conn.close()
    
    def record_fault_event(self, cp_id: str, event_type: str, reason: str = ""):
        """
        Record a fault or recovery event.
        
        Args:
            cp_id: Charging point ID
            event_type: 'FAULT' or 'RECOVERY'
            reason: Description of the fault/recovery
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO fault_events (cp_id, event_type, reason, timestamp)
                VALUES (?, ?, ?, ?)
            """, (cp_id, event_type, reason, timestamp))
            conn.commit()
    
    def record_health_snapshot(
        self,
        cp_id: str,
        is_healthy: bool,
        state: str,
        circuit_state: str,
        failure_count: int = 0
    ):
        """
        Record a health status snapshot.
        
        Args:
            cp_id: Charging point ID
            is_healthy: Current health status
            state: CP state (e.g., 'ACTIVATED', 'SUPPLYING')
            circuit_state: Circuit breaker state
            failure_count: Number of consecutive failures
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cp_health_history 
                (cp_id, is_healthy, state, circuit_state, failure_count, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cp_id, is_healthy, state, circuit_state, failure_count, timestamp))
            conn.commit()
    
    def start_charging_session(
        self,
        session_id: str,
        cp_id: str,
        driver_id: str
    ):
        """
        Record the start of a charging session.
        
        Args:
            session_id: Unique session identifier
            cp_id: Charging point ID
            driver_id: Driver identifier
        """
        start_time = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO charging_sessions 
                (session_id, cp_id, driver_id, start_time, status)
                VALUES (?, ?, ?, ?, 'ACTIVE')
            """, (session_id, cp_id, driver_id, start_time))
            conn.commit()
    
    def end_charging_session(
        self,
        session_id: str,
        total_kwh: float,
        total_cost: float,
        status: str = "COMPLETED"
    ):
        """
        Record the end of a charging session.
        
        Args:
            session_id: Unique session identifier
            total_kwh: Total energy delivered
            total_cost: Total cost
            status: Session status ('COMPLETED' or 'FAILED')
        """
        end_time = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE charging_sessions
                SET end_time = ?, total_kwh = ?, total_cost = ?, status = ?
                WHERE session_id = ?
            """, (end_time, total_kwh, total_cost, status, session_id))
            conn.commit()
    
    def update_session_energy(
        self,
        session_id: str,
        kwh: float,
        cost: float
    ):
        """
        Update the current energy and cost of an active session.
        
        Args:
            session_id: Unique session identifier
            kwh: Current total energy delivered
            cost: Current total cost
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE charging_sessions
                SET total_kwh = ?, total_cost = ?
                WHERE session_id = ? AND status = 'ACTIVE'
            """, (kwh, cost, session_id))
            conn.commit()
    
    def get_fault_history(
        self,
        cp_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get fault event history.
        
        Args:
            cp_id: Filter by charging point ID (None for all)
            limit: Maximum number of records to return
            
        Returns:
            List of fault event dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if cp_id:
                cursor.execute("""
                    SELECT * FROM fault_events
                    WHERE cp_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (cp_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM fault_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_health_history(
        self,
        cp_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get health status history for a CP.
        
        Args:
            cp_id: Charging point ID
            limit: Maximum number of records to return
            
        Returns:
            List of health snapshot dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM cp_health_history
                WHERE cp_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (cp_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_session_history(
        self,
        cp_id: Optional[str] = None,
        driver_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get charging session history.
        
        Args:
            cp_id: Filter by charging point ID (None for all)
            driver_id: Filter by driver ID (None for all)
            limit: Maximum number of records to return
            
        Returns:
            List of charging session dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM charging_sessions WHERE 1=1"
            params = []
            
            if cp_id:
                query += " AND cp_id = ?"
                params.append(cp_id)
            
            if driver_id:
                query += " AND driver_id = ?"
                params.append(driver_id)
            
            query += " ORDER BY start_time DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_fault_statistics(self, cp_id: Optional[str] = None) -> Dict:
        """
        Get fault statistics.
        
        Args:
            cp_id: Filter by charging point ID (None for all)
            
        Returns:
            Dictionary with fault statistics
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if cp_id:
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_events,
                        SUM(CASE WHEN event_type = 'FAULT' THEN 1 ELSE 0 END) as fault_count,
                        SUM(CASE WHEN event_type = 'RECOVERY' THEN 1 ELSE 0 END) as recovery_count
                    FROM fault_events
                    WHERE cp_id = ?
                """, (cp_id,))
            else:
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_events,
                        SUM(CASE WHEN event_type = 'FAULT' THEN 1 ELSE 0 END) as fault_count,
                        SUM(CASE WHEN event_type = 'RECOVERY' THEN 1 ELSE 0 END) as recovery_count
                    FROM fault_events
                """)
            
            row = cursor.fetchone()
            return dict(row) if row else {}
