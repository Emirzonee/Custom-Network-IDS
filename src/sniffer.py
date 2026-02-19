import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from src.logger import setup_logger
from src.database_manager import DatabaseManager
from typing import Optional, Any, Dict, List

class NetworkSniffer:
    def __init__(self, interface: Optional[str] = None):
        self.logger = setup_logger("IDS_SNIFFER")
        self.interface = interface
        self.is_running = False
        
        # Veritabanı motorunu çalıştır
        self.db = DatabaseManager()
        
        self.syn_tracker: Dict[str, List[float]] = defaultdict(list)
        self.TIME_WINDOW = 10.0  
        self.SYN_THRESHOLD = 20  

    def analyze_packet(self, packet: Any, src_ip: str, dst_ip: str) -> None:
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            current_time = time.time()
            
            self.syn_tracker[src_ip].append(current_time)
            self.syn_tracker[src_ip] = [
                t for t in self.syn_tracker[src_ip] 
                if current_time - t <= self.TIME_WINDOW
            ]
            
            syn_count = len(self.syn_tracker[src_ip])
            
            if syn_count > self.SYN_THRESHOLD:
                self.logger.critical(
                    f"🚨 [SALDIRI TESPİT EDİLDİ] Olası SYN Flood / Port Tarama! "
                    f"Kaynak: {src_ip} -> Hedef: {dst_ip} ({self.TIME_WINDOW} saniyede {syn_count} paket!)"
                )
                
                # SİHİRLİ KISIM: Saldırıyı veritabanına yaz
                self.db.add_attack(src_ip, dst_ip, syn_count)
                
                self.syn_tracker[src_ip] = []

    def packet_handler(self, packet: Any) -> None:
        try:
            if packet.haslayer(IP):
                src_ip: str = packet[IP].src
                dst_ip: str = packet[IP].dst
                self.analyze_packet(packet, src_ip, dst_ip)
        except Exception as e:
            self.logger.error(f"Paket işleme hatası: {e}")

    def start(self, packet_count: int = 0) -> None:
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