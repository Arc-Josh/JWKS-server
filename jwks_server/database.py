# jwks_server/database.py
"""
Database utilities for SQLite storage of private keys.
Handles secure database operations with parameterized queries to prevent SQL injection.
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Tuple, Optional


class DatabaseManager:
    """Manages SQLite database operations for private key storage."""
    
    def __init__(self, db_file: str = "totally_not_my_privateKeys.db"):
        """Initialize database connection and create schema if needed."""
        self.db_file = db_file
        self._init_database()
    
    def _init_database(self):
        """Create the database file and initialize the schema."""
        with sqlite3.connect(self.db_file) as conn:
            # Create the keys table with the specified schema
            conn.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)
            conn.commit()
    
    def save_key(self, key_pem: bytes, expiry_timestamp: int) -> int:
        """
        Save a private key to the database.
        
        Args:
            key_pem: Private key in PEM format (bytes)
            expiry_timestamp: Unix timestamp when the key expires
            
        Returns:
            The kid (key ID) assigned by the database
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (key_pem, expiry_timestamp)
            )
            conn.commit()
            return cursor.lastrowid
    
    def get_valid_keys(self, now_timestamp: int) -> List[Tuple[int, bytes, int]]:
        """
        Get all valid (non-expired) keys from the database.
        
        Args:
            now_timestamp: Current Unix timestamp
            
        Returns:
            List of tuples: (kid, key_pem, expiry_timestamp)
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC",
                (now_timestamp,)
            )
            return cursor.fetchall()
    
    def get_expired_keys(self, now_timestamp: int) -> List[Tuple[int, bytes, int]]:
        """
        Get all expired keys from the database.
        
        Args:
            now_timestamp: Current Unix timestamp
            
        Returns:
            List of tuples: (kid, key_pem, expiry_timestamp)
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid ASC",
                (now_timestamp,)
            )
            return cursor.fetchall()
    
    def get_key_by_id(self, kid: int) -> Optional[Tuple[int, bytes, int]]:
        """
        Get a specific key by its ID.
        
        Args:
            kid: Key ID to retrieve
            
        Returns:
            Tuple of (kid, key_pem, expiry_timestamp) or None if not found
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE kid = ?",
                (kid,)
            )
            return cursor.fetchone()
    
    def cleanup_expired_keys(self, now_timestamp: int) -> int:
        """
        Remove expired keys from the database (optional cleanup).
        
        Args:
            now_timestamp: Current Unix timestamp
            
        Returns:
            Number of keys deleted
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "DELETE FROM keys WHERE exp <= ?",
                (now_timestamp,)
            )
            conn.commit()
            return cursor.rowcount