from src.sniffer import NetworkSniffer
from src.logger import setup_logger

def main() -> None:
    # Ana sistem loglayıcısını başlat
    logger = setup_logger("IDS_MAIN")
    logger.info("Custom Network IDS/IPS Sistemi Başlatılıyor...")
    
    # Sniffer nesnesini oluştur ve başlat
    # Arayüzü None bırakıyoruz ki Scapy aktif Wi-Fi veya Ethernet'i otomatik bulsun
    ids_sniffer = NetworkSniffer(interface=None)
    
    try:
        # Şimdilik test amaçlı sonsuza kadar (0) dinle
        ids_sniffer.start(packet_count=0)
    except Exception as e:
        logger.critical(f"Sistem çökmesi: {e}")

if __name__ == "__main__":
    main()