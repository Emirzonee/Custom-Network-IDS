import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from src.logger import setup_logger
from typing import Optional, Any, Dict, List

class NetworkSniffer:
    def __init__(self, interface: Optional[str] = None):
        """
        Gelişmiş IDS Sniffer sınıfı. Ağ trafiğini analiz eder ve istatistiksel anomali tespiti yapar.
        """
        self.logger = setup_logger("IDS_SNIFFER")
        self.interface = interface
        self.is_running = False
        
        # --- İSTATİSTİKSEL ANALİZ MOTORU AYARLARI ---
        # Hangi IP'nin ne zaman SYN paketi attığını tutacak hafıza: { '192.168.1.5': [zaman1, zaman2, ...] }
        self.syn_tracker: Dict[str, List[float]] = defaultdict(list)
        
        self.TIME_WINDOW = 10.0  # Saniye cinsinden takip süresi (Örn: Son 10 saniye)
        self.SYN_THRESHOLD = 20  # Bu süre içindeki maksimum normal SYN paketi sayısı

    def analyze_packet(self, packet: Any, src_ip: str, dst_ip: str) -> None:
        """
        Gelen paketleri istatistiksel olarak inceler. (SYN Flood ve Port Tarama Tespiti)
        """
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            current_time = time.time()
            
            # 1. Bu IP'nin listesine şu anki zamanı ekle
            self.syn_tracker[src_ip].append(current_time)
            
            # 2. Zaman penceresinden (son 10 saniye) daha eski olan, tarihi geçmiş kayıtları temizle
            self.syn_tracker[src_ip] = [
                t for t in self.syn_tracker[src_ip] 
                if current_time - t <= self.TIME_WINDOW
            ]
            
            # 3. Kalan paket sayısını say (Eşik değerini aştı mı?)
            syn_count = len(self.syn_tracker[src_ip])
            
            if syn_count > self.SYN_THRESHOLD:
                self.logger.critical(
                    f"🚨 [SALDIRI TESPİT EDİLDİ] Olası SYN Flood / Port Tarama! "
                    f"Kaynak: {src_ip} -> Hedef: {dst_ip} ({self.TIME_WINDOW} saniyede {syn_count} paket!)"
                )
                # Sürekli aynı uyarıyı basıp terminali kilitlememek için IP'nin sayacını sıfırla
                self.syn_tracker[src_ip] = []

    def packet_handler(self, packet: Any) -> None:
        """
        Her yakalanan paket bu fonksiyondan geçer.
        """
        try:
            if packet.haslayer(IP):
                src_ip: str = packet[IP].src
                dst_ip: str = packet[IP].dst
                
                # Paketi doğrudan analiz motoruna gönder
                self.analyze_packet(packet, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.error(f"Paket işleme hatası: {e}")

    def start(self, packet_count: int = 0) -> None:
        """
        Ağ dinlemesini başlatır. store=False RAM şişmesini önler.
        """
        self.logger.info(f"Gelişmiş Ağ Dinlemesi Başlatılıyor... (Arayüz: {self.interface or 'Varsayılan'})")
        self.logger.info(f"Kural: {self.TIME_WINDOW} saniyede {self.SYN_THRESHOLD}'den fazla SYN paketi atan IP uyarılır.")
        self.is_running = True
        
        try:
            sniff(
                iface=self.interface, 
                prn=self.packet_handler, 
                store=False, 
                count=packet_count
            )
        except KeyboardInterrupt:
            self.logger.info("Kullanıcı müdahalesi: Sistem durduruluyor.")
        except Exception as e:
            self.logger.critical(f"Sniffer kritik hatası: {e}")
        finally:
            self.is_running = False
            self.logger.info("Ağ dinlemesi sonlandırıldı.")