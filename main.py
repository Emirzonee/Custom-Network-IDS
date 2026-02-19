from src.logger import setup_logger
from src.sniffer import NetworkSniffer


def main() -> None:
    """
    Entry point for the IDS engine.

    Initializes the sniffer and starts packet capture. The interface is set
    to None so Scapy automatically selects the active network adapter.
    Run with administrator / root privileges — raw packet capture requires it.
    """
    logger = setup_logger("IDS_MAIN")
    logger.info("Custom Network IDS/IPS starting...")

    sniffer = NetworkSniffer(interface=None)

    try:
        sniffer.start(packet_count=0)
    except Exception as e:
        logger.critical(f"System crash: {e}")


if __name__ == "__main__":
    main()