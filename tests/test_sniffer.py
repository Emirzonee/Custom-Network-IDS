import pytest
from unittest.mock import MagicMock
from src.sniffer import NetworkSniffer
from scapy.all import IP, TCP

# @pytest.fixture: Testlerden önce hazırlık yapan yardımcıdır.
# Her test fonksiyonu için sıfırdan, tertemiz bir sniffer üretir.
@pytest.fixture
def sniffer():
    snif = NetworkSniffer()
    # Logları ekrana basmasın, sadece "çağrıldı mı?" diye takip etsin diye 'sahte' (Mock) logger takıyoruz.
    snif.logger = MagicMock()
    
    # Testleri hızlandırmak için limitleri düşürelim
    snif.TIME_WINDOW = 2.0  # 2 saniyelik pencere
    snif.SYN_THRESHOLD = 5  # 5 paketten fazlası saldırı sayılsın
    return snif

def test_normal_traffic(sniffer):
    """
    Senaryo 1: Eşik değerin altında kalan normal trafik alarm vermemeli.
    """
    # Sahte bir IP paketi oluştur (1.1.1.1'den geliyor)
    packet = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(flags="S")
    
    # Eşik değerimiz 5, biz sadece 3 tane gönderelim
    for _ in range(3):
        sniffer.analyze_packet(packet, "1.1.1.1", "2.2.2.2")
    
    # KONTROL: Logger.critical (Kritik Hata) HİÇ çağrılmamış olmalı
    sniffer.logger.critical.assert_not_called()

def test_syn_flood_attack(sniffer):
    """
    Senaryo 2: Eşik değer aşılınca sistem alarm vermeli.
    """
    packet = IP(src="6.6.6.6", dst="2.2.2.2")/TCP(flags="S")
    
    # Eşik değerimiz 5, biz 10 tane saldırı paketi gönderelim
    for _ in range(10):
        sniffer.analyze_packet(packet, "6.6.6.6", "2.2.2.2")
    
    # KONTROL: Logger.critical en az bir kere çağrılmış olmalı!
    sniffer.logger.critical.assert_called()