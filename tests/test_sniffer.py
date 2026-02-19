import pytest
from unittest.mock import MagicMock, patch

from scapy.all import IP, TCP

from src.sniffer import NetworkSniffer


@pytest.fixture
def sniffer():
    """
    Provides a NetworkSniffer instance with a mock logger and mock database.

    Thresholds are lowered to keep tests fast:
      - TIME_WINDOW: 2 seconds
      - SYN_THRESHOLD: 5 packets
    """
    with patch("src.sniffer.DatabaseManager"):
        snif = NetworkSniffer()
        snif.logger = MagicMock()
        snif.TIME_WINDOW = 2.0
        snif.SYN_THRESHOLD = 5
        yield snif


def test_normal_traffic_does_not_trigger_alert(sniffer):
    """
    Traffic below the threshold should not produce a CRITICAL log entry.
    """
    packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags="S")

    for _ in range(3):  # 3 < SYN_THRESHOLD (5)
        sniffer.analyze_packet(packet, "1.1.1.1", "2.2.2.2")

    sniffer.logger.critical.assert_not_called()


def test_syn_flood_triggers_alert(sniffer):
    """
    Traffic exceeding the threshold should produce at least one CRITICAL log entry.
    """
    packet = IP(src="6.6.6.6", dst="2.2.2.2") / TCP(flags="S")

    for _ in range(10):  # 10 > SYN_THRESHOLD (5)
        sniffer.analyze_packet(packet, "6.6.6.6", "2.2.2.2")

    sniffer.logger.critical.assert_called()


def test_tracker_resets_after_attack(sniffer):
    """
    After an attack is detected, the SYN tracker for that IP should be reset
    to prevent duplicate alerts for the same burst.
    """
    packet = IP(src="9.9.9.9", dst="2.2.2.2") / TCP(flags="S")

    for _ in range(10):
        sniffer.analyze_packet(packet, "9.9.9.9", "2.2.2.2")

    assert sniffer.syn_tracker["9.9.9.9"] == []


def test_non_syn_packets_are_ignored(sniffer):
    """
    ACK packets should not increment the SYN counter.
    """
    packet = IP(src="3.3.3.3", dst="2.2.2.2") / TCP(flags="A")  # ACK, not SYN

    for _ in range(20):
        sniffer.analyze_packet(packet, "3.3.3.3", "2.2.2.2")

    sniffer.logger.critical.assert_not_called()