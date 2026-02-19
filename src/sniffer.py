import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

import yaml
from scapy.all import IP, TCP, sniff

from src.database_manager import DatabaseManager
from src.logger import setup_logger

CONFIG_PATH = "config.yaml"
DEFAULT_TIME_WINDOW = 10.0
DEFAULT_SYN_THRESHOLD = 20


def _load_config() -> dict:
    """Loads config.yaml. Returns an empty dict if the file is missing."""
    try:
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


class NetworkSniffer:
    """
    Captures live network traffic and detects SYN Flood / Port Scan attacks.

    Uses a sliding time window to count SYN packets per source IP. When the
    count exceeds SYN_THRESHOLD within TIME_WINDOW seconds, the event is
    logged as an attack and written to the database.

    Detection thresholds and database path are read from config.yaml at startup.
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self.logger = setup_logger("IDS_SNIFFER")
        self.is_running = False

        config = _load_config()
        network_cfg = config.get("network", {})
        db_cfg = config.get("database", {})

        self.interface = interface or network_cfg.get("interface")
        self.TIME_WINDOW: float = network_cfg.get("time_window", DEFAULT_TIME_WINDOW)
        self.SYN_THRESHOLD: int = network_cfg.get("syn_threshold", DEFAULT_SYN_THRESHOLD)

        db_path = db_cfg.get("path", "logs/attacks.db")
        self.db = DatabaseManager(db_path=db_path)

        self.syn_tracker: Dict[str, List[float]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Packet analysis
    # ------------------------------------------------------------------

    def analyze_packet(self, packet: Any, src_ip: str, dst_ip: str) -> None:
        """
        Checks whether a packet contributes to a SYN Flood pattern.

        Maintains a per-IP list of SYN packet timestamps. Timestamps older
        than TIME_WINDOW are pruned on each call. If the count exceeds
        SYN_THRESHOLD, an attack event is recorded and the tracker is reset
        to avoid duplicate alerts for the same burst.

        Args:
            packet: Scapy packet object.
            src_ip: Source IP address extracted from the IP layer.
            dst_ip: Destination IP address extracted from the IP layer.
        """
        if not (packet.haslayer(TCP) and packet[TCP].flags == "S"):
            return

        current_time = time.time()

        # Sliding window: keep only timestamps within TIME_WINDOW
        self.syn_tracker[src_ip].append(current_time)
        self.syn_tracker[src_ip] = [
            t for t in self.syn_tracker[src_ip]
            if current_time - t <= self.TIME_WINDOW
        ]

        syn_count = len(self.syn_tracker[src_ip])

        if syn_count > self.SYN_THRESHOLD:
            self.logger.critical(
                f"Attack detected: SYN Flood / Port Scan | "
                f"src={src_ip} dst={dst_ip} | "
                f"{syn_count} SYN packets in {self.TIME_WINDOW}s"
            )
            self.db.add_attack(src_ip, dst_ip, syn_count)

            # Reset tracker to suppress duplicate alerts for the same burst
            self.syn_tracker[src_ip] = []

    def packet_handler(self, packet: Any) -> None:
        """
        Callback passed to scapy's sniff(). Filters for IP packets only.

        Args:
            packet: Raw packet captured from the network interface.
        """
        try:
            if packet.haslayer(IP):
                self.analyze_packet(packet, packet[IP].src, packet[IP].dst)
        except Exception as e:
            self.logger.error(f"Packet processing error: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, packet_count: int = 0) -> None:
        """
        Starts the packet capture loop.

        Args:
            packet_count: Number of packets to capture before stopping.
                          0 means capture indefinitely.
        """
        self.logger.info(
            f"Starting network capture | "
            f"interface={self.interface or 'auto'} | "
            f"threshold={self.SYN_THRESHOLD} SYN/{self.TIME_WINDOW}s"
        )
        self.is_running = True

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                count=packet_count,
            )
        except KeyboardInterrupt:
            self.logger.info("Capture stopped by user.")
        except Exception as e:
            self.logger.critical(f"Sniffer fatal error: {e}")
        finally:
            self.is_running = False
            self.logger.info("Network capture terminated.")