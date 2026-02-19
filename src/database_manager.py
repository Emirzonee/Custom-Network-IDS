import os
import sqlite3
from datetime import datetime


class DatabaseManager:
    """
    Manages SQLite storage for detected attack events.

    The database is created automatically on first run. All writes use
    context managers to ensure connections are closed cleanly.
    """

    CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS attacks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    DATETIME,
            src_ip       TEXT,
            dst_ip       TEXT,
            packet_count INTEGER,
            attack_type  TEXT
        )
    """

    def __init__(self, db_path: str = "logs/attacks.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Creates the attacks table if it does not already exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(self.CREATE_TABLE_SQL)

    def add_attack(
        self,
        src_ip: str,
        dst_ip: str,
        packet_count: int,
        attack_type: str = "SYN Flood",
    ) -> None:
        """
        Inserts a detected attack record into the database.

        Args:
            src_ip:       Source IP address of the attacker.
            dst_ip:       Destination IP that was targeted.
            packet_count: Number of SYN packets observed in the time window.
            attack_type:  Classification label (default: 'SYN Flood').
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO attacks (timestamp, src_ip, dst_ip, packet_count, attack_type) "
                "VALUES (?, ?, ?, ?, ?)",
                (datetime.now(), src_ip, dst_ip, packet_count, attack_type),
            )