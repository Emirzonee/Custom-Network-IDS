import logging
import os
from datetime import datetime

def setup_logger(name: str) -> logging.Logger:
    """
    Sistem genelinde kullanılacak profesyonel loglama yapılandırması.
    Hem ekrana hem de dosyaya kayıt alır.
    """
    logger = logging.getLogger(name)
    
    # Eğer logger daha önce ayarlandıysa tekrar ayarlama (Çift kayıt olmasın)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        
        # Format: 2026-02-19 14:30:01 - [INFO] - IDS_SYSTEM : Mesaj
        formatter = logging.Formatter(
            '%(asctime)s - [%(levelname)s] - %(name)s : %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 1. Çıktı: Terminale sadece önemli bilgileri yaz (INFO)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # 2. Çıktı: Dosyaya her şeyi yaz (DEBUG dahil)
        # 'logs' klasörünün varlığını garantiye al
        log_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(log_dir, exist_ok=True)
            
        log_file = os.path.join(log_dir, f"ids_log_{datetime.now().strftime('%Y%m%d')}.txt")
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
    return logger
