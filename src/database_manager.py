import sqlite3
from datetime import datetime
import os

class DatabaseManager:
    def __init__(self, db_path="logs/attacks.db"):
        self.db_path = db_path
        # Klasör yoksa oluştur
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def init_db(self):
        """Saldırı kayıtları tablosunu oluşturur."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    packet_count INTEGER,
                    attack_type TEXT
                )
            ''')

    def add_attack(self, src_ip, dst_ip, packet_count, attack_type="SYN Flood"):
        """Tespit edilen saldırıyı veritabanına kaydeder."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO attacks (timestamp, src_ip, dst_ip, packet_count, attack_type) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(), src_ip, dst_ip, packet_count, attack_type)
            )