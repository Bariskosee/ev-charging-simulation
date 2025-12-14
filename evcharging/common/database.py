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
            
            # CP Registry tables for EV_Registry module
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cp_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cp_id TEXT NOT NULL UNIQUE,
                    location TEXT NOT NULL,
                    credentials_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'REGISTERED',
                    registration_date TEXT NOT NULL,
                    deregistration_date TEXT,
                    last_authenticated TEXT,
                    certificate_fingerprint TEXT,
                    metadata TEXT,
                    token_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for CP registry
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_registry_cp_id 
                ON cp_registry(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_registry_status 
                ON cp_registry(status)
            """)
            
            # CP encryption keys table for EV_Central security
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cp_encryption_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cp_id TEXT NOT NULL UNIQUE,
                    key_hash TEXT NOT NULL,
                    encrypted_key TEXT,
                    key_created_at TEXT NOT NULL,
                    key_rotated_at TEXT,
                    key_version INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # CP security status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cp_security_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cp_id TEXT NOT NULL UNIQUE,
                    registration_status TEXT NOT NULL DEFAULT 'ACTIVE',
                    last_authenticated_at TEXT,
                    auth_failure_count INTEGER DEFAULT 0,
                    last_auth_failure_at TEXT,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    out_of_service_at TEXT,
                    out_of_service_reason TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for security tables
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_keys_cp_id 
                ON cp_encryption_keys(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_keys_status 
                ON cp_encryption_keys(status)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_security_cp_id 
                ON cp_security_status(cp_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cp_security_status 
                ON cp_security_status(registration_status)
            """)
            
            # Migration: Add token_version column if it doesn't exist
            cursor.execute("PRAGMA table_info(cp_registry)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'token_version' not in columns:
                cursor.execute("""
                    ALTER TABLE cp_registry 
                    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1
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


class CPRegistryDB:
    """Database manager for CP registry and authentication."""
    
    def __init__(self, db_path: str = "ev_charging.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        # Ensure tables exist by initializing the parent database
        FaultHistoryDB(db_path)
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def register_cp(
        self,
        cp_id: str,
        location: str,
        credentials_hash: str,
        certificate_fingerprint: Optional[str] = None,
        metadata: Optional[str] = None
    ) -> bool:
        """
        Register a new charging point or update existing registration.
        
        Args:
            cp_id: Charging point identifier
            location: CP location (city or address)
            credentials_hash: Hashed credentials for authentication
            certificate_fingerprint: Optional SSL certificate fingerprint
            metadata: Optional JSON metadata
            
        Returns:
            True if registered successfully, False if already registered
        """
        registration_date = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if CP already exists
            cursor.execute("SELECT status FROM cp_registry WHERE cp_id = ?", (cp_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing registration
                cursor.execute("""
                    UPDATE cp_registry
                    SET location = ?, credentials_hash = ?, status = 'REGISTERED',
                        deregistration_date = NULL, certificate_fingerprint = ?,
                        metadata = ?, updated_at = ?
                    WHERE cp_id = ?
                """, (location, credentials_hash, certificate_fingerprint, 
                      metadata, registration_date, cp_id))
                conn.commit()
                return False  # Was already registered
            else:
                # Insert new registration
                cursor.execute("""
                    INSERT INTO cp_registry 
                    (cp_id, location, credentials_hash, status, registration_date,
                     certificate_fingerprint, metadata, updated_at)
                    VALUES (?, ?, ?, 'REGISTERED', ?, ?, ?, ?)
                """, (cp_id, location, credentials_hash, registration_date,
                      certificate_fingerprint, metadata, registration_date))
                conn.commit()
                return True  # New registration
    
    def deregister_cp(self, cp_id: str) -> bool:
        """
        Deregister a charging point and invalidate all existing tokens.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if deregistered successfully, False if not found or already deregistered
        """
        deregistration_date = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Increment token_version to invalidate all existing JWTs
            cursor.execute("""
                UPDATE cp_registry
                SET status = 'DEREGISTERED', deregistration_date = ?, 
                    token_version = token_version + 1, updated_at = ?
                WHERE cp_id = ? AND status = 'REGISTERED'
            """, (deregistration_date, deregistration_date, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def get_cp(self, cp_id: str) -> Optional[Dict]:
        """
        Get CP registration details.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Dictionary with CP details or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cp_id, location, status, registration_date, deregistration_date,
                       last_authenticated, certificate_fingerprint, metadata, token_version,
                       created_at, updated_at
                FROM cp_registry
                WHERE cp_id = ?
            """, (cp_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_token_version(self, cp_id: str) -> Optional[int]:
        """
        Get current token version for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Token version or None if CP not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT token_version FROM cp_registry WHERE cp_id = ?
            """, (cp_id,))
            
            row = cursor.fetchone()
            if row:
                return row['token_version']
            return None
    
    def increment_token_version(self, cp_id: str) -> bool:
        """
        Increment token version to invalidate all existing tokens.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if incremented successfully, False if CP not found
        """
        updated_at = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_registry
                SET token_version = token_version + 1, updated_at = ?
                WHERE cp_id = ?
            """, (updated_at, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def get_cp_credentials(self, cp_id: str) -> Optional[str]:
        """
        Get CP credentials hash for authentication.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Credentials hash or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT credentials_hash
                FROM cp_registry
                WHERE cp_id = ? AND status = 'REGISTERED'
            """, (cp_id,))
            
            row = cursor.fetchone()
            return row['credentials_hash'] if row else None
    
    def update_last_authenticated(self, cp_id: str):
        """
        Update last authentication timestamp for a CP.
        
        Args:
            cp_id: Charging point identifier
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_registry
                SET last_authenticated = ?, updated_at = ?
                WHERE cp_id = ?
            """, (timestamp, timestamp, cp_id))
            conn.commit()
    
    def list_cps(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """
        List all registered CPs with optional filtering.
        
        Args:
            status: Filter by status ('REGISTERED', 'DEREGISTERED', or None for all)
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of CP dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT cp_id, location, status, registration_date, deregistration_date,
                       last_authenticated, certificate_fingerprint, metadata,
                       created_at, updated_at
                FROM cp_registry
            """
            params = []
            
            if status:
                query += " WHERE status = ?"
                params.append(status)
            
            query += " ORDER BY registration_date DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def count_cps(self, status: Optional[str] = None) -> int:
        """
        Count CPs with optional status filter.
        
        Args:
            status: Filter by status or None for all
            
        Returns:
            Count of CPs
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if status:
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM cp_registry
                    WHERE status = ?
                """, (status,))
            else:
                cursor.execute("SELECT COUNT(*) as count FROM cp_registry")
            
            row = cursor.fetchone()
            return row['count'] if row else 0


class CPSecurityDB:
    """Database manager for CP security, encryption keys, and status management."""
    
    def __init__(self, db_path: str = "ev_charging.db"):
        """
        Initialize security database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        # Ensure tables exist by initializing the parent database
        FaultHistoryDB(db_path)
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # ==================== Encryption Key Management ====================
    
    def store_encryption_key(self, cp_id: str, key_hash: str, encrypted_key: Optional[str] = None) -> bool:
        """
        Store a new encryption key for a CP.
        
        Args:
            cp_id: Charging point identifier
            key_hash: Hash of the encryption key
            encrypted_key: Wrapped (encrypted) key for secure storage
            
        Returns:
            True if stored successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if key already exists
            cursor.execute("SELECT id, key_version FROM cp_encryption_keys WHERE cp_id = ?", (cp_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing key (rotation)
                new_version = existing['key_version'] + 1
                cursor.execute("""
                    UPDATE cp_encryption_keys
                    SET key_hash = ?, encrypted_key = ?, key_rotated_at = ?, key_version = ?, 
                        updated_at = ?, status = 'ACTIVE'
                    WHERE cp_id = ?
                """, (key_hash, encrypted_key, timestamp, new_version, timestamp, cp_id))
            else:
                # Insert new key
                cursor.execute("""
                    INSERT INTO cp_encryption_keys 
                    (cp_id, key_hash, encrypted_key, key_created_at, key_version, status, updated_at)
                    VALUES (?, ?, ?, ?, 1, 'ACTIVE', ?)
                """, (cp_id, key_hash, encrypted_key, timestamp, timestamp))
            
            conn.commit()
            return True
    
    def get_encryption_key_hash(self, cp_id: str) -> Optional[str]:
        """
        Get the current encryption key hash for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Key hash or None if not found or revoked
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_hash
                FROM cp_encryption_keys
                WHERE cp_id = ? AND status = 'ACTIVE'
            """, (cp_id,))
            
            row = cursor.fetchone()
            return row['key_hash'] if row else None
    
    def revoke_encryption_key(self, cp_id: str) -> bool:
        """
        Revoke a CP's encryption key.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if revoked successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_encryption_keys
                SET status = 'REVOKED', updated_at = ?
                WHERE cp_id = ? AND status = 'ACTIVE'
            """, (timestamp, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def get_key_info(self, cp_id: str) -> Optional[Dict]:
        """
        Get encryption key metadata for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Dictionary with key metadata (including encrypted_key) or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cp_id, key_hash, encrypted_key, key_created_at, key_rotated_at, 
                       key_version, status, updated_at
                FROM cp_encryption_keys
                WHERE cp_id = ?
            """, (cp_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_unmigrated_keys(self) -> list[str]:
        """
        Find CPs that have key_hash but no encrypted_key (need migration).
        
        Returns:
            List of CP IDs that need key migration
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cp_id
                FROM cp_encryption_keys
                WHERE key_hash IS NOT NULL 
                  AND (encrypted_key IS NULL OR encrypted_key = '')
                  AND status = 'ACTIVE'
            """)
            
            return [row['cp_id'] for row in cursor.fetchall()]
    
    # ==================== CP Security Status Management ====================
    
    def initialize_cp_security(self, cp_id: str) -> bool:
        """
        Initialize security status for a newly registered CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if initialized successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if already exists
            cursor.execute("SELECT id FROM cp_security_status WHERE cp_id = ?", (cp_id,))
            if cursor.fetchone():
                # Update to ACTIVE if exists
                cursor.execute("""
                    UPDATE cp_security_status
                    SET registration_status = 'ACTIVE', 
                        revoked_at = NULL, 
                        revocation_reason = NULL,
                        out_of_service_at = NULL,
                        out_of_service_reason = NULL,
                        auth_failure_count = 0,
                        updated_at = ?
                    WHERE cp_id = ?
                """, (timestamp, cp_id))
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO cp_security_status 
                    (cp_id, registration_status, updated_at)
                    VALUES (?, 'ACTIVE', ?)
                """, (cp_id, timestamp))
            
            conn.commit()
            return True
    
    def get_cp_security_status(self, cp_id: str) -> Optional[Dict]:
        """
        Get security status for a CP.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            Dictionary with security status or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cp_id, registration_status, last_authenticated_at,
                       auth_failure_count, last_auth_failure_at,
                       revoked_at, revocation_reason,
                       out_of_service_at, out_of_service_reason,
                       created_at, updated_at
                FROM cp_security_status
                WHERE cp_id = ?
            """, (cp_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def set_registration_status(self, cp_id: str, status: str, reason: str = "") -> bool:
        """
        Set the registration status for a CP.
        
        Args:
            cp_id: Charging point identifier
            status: New status (ACTIVE, OUT_OF_SERVICE, REVOKED)
            reason: Reason for status change
            
        Returns:
            True if updated successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Update the registration status
            cursor.execute("""
                UPDATE cp_security_status
                SET registration_status = ?, updated_at = ?
                WHERE cp_id = ?
            """, (status, timestamp, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def record_successful_auth(self, cp_id: str):
        """
        Record successful authentication for a CP.
        
        Args:
            cp_id: Charging point identifier
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_security_status
                SET last_authenticated_at = ?, 
                    auth_failure_count = 0,
                    updated_at = ?
                WHERE cp_id = ?
            """, (timestamp, timestamp, cp_id))
            conn.commit()
    
    def record_auth_failure(self, cp_id: str):
        """
        Record authentication failure for a CP.
        
        Args:
            cp_id: Charging point identifier
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_security_status
                SET auth_failure_count = auth_failure_count + 1,
                    last_auth_failure_at = ?,
                    updated_at = ?
                WHERE cp_id = ?
            """, (timestamp, timestamp, cp_id))
            conn.commit()
    
    def revoke_cp(self, cp_id: str, reason: str = "Manual revocation") -> bool:
        """
        Revoke a CP's access (SECURITY CRITICAL).
        
        Args:
            cp_id: Charging point identifier
            reason: Reason for revocation
            
        Returns:
            True if revoked successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_security_status
                SET registration_status = 'REVOKED',
                    revoked_at = ?,
                    revocation_reason = ?,
                    updated_at = ?
                WHERE cp_id = ? AND registration_status != 'REVOKED'
            """, (timestamp, reason, timestamp, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def set_out_of_service(self, cp_id: str, reason: str = "Maintenance") -> bool:
        """
        Mark a CP as out of service.
        
        Args:
            cp_id: Charging point identifier
            reason: Reason for out-of-service status
            
        Returns:
            True if updated successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_security_status
                SET registration_status = 'OUT_OF_SERVICE',
                    out_of_service_at = ?,
                    out_of_service_reason = ?,
                    updated_at = ?
                WHERE cp_id = ? AND registration_status = 'ACTIVE'
            """, (timestamp, reason, timestamp, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def restore_to_active(self, cp_id: str) -> bool:
        """
        Restore a CP from OUT_OF_SERVICE to ACTIVE.
        
        Args:
            cp_id: Charging point identifier
            
        Returns:
            True if restored successfully
        """
        timestamp = utc_now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cp_security_status
                SET registration_status = 'ACTIVE',
                    out_of_service_at = NULL,
                    out_of_service_reason = NULL,
                    updated_at = ?
                WHERE cp_id = ? AND registration_status = 'OUT_OF_SERVICE'
            """, (timestamp, cp_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def list_cps_by_status(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """
        List CPs with optional status filtering.
        
        Args:
            status: Filter by status ('ACTIVE', 'REVOKED', 'OUT_OF_SERVICE', or None for all)
            limit: Maximum number of records
            offset: Number of records to skip
            
        Returns:
            List of CP security status dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT cp_id, registration_status, last_authenticated_at,
                       auth_failure_count, last_auth_failure_at,
                       revoked_at, revocation_reason,
                       out_of_service_at, out_of_service_reason,
                       created_at, updated_at
                FROM cp_security_status
            """
            params = []
            
            if status:
                query += " WHERE registration_status = ?"
                params.append(status)
            
            query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
