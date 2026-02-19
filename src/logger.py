import logging
import os
from datetime import datetime


def setup_logger(name: str) -> logging.Logger:
    """
    Creates a named logger that writes to both the console and a daily log file.

    Console output is limited to INFO and above. The log file captures
    everything including DEBUG. Log files are stored in the 'logs/' directory
    and named by date (e.g. ids_log_20260219.txt).

    Args:
        name: Logger name shown in each log line.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - [%(levelname)s] - %(name)s : %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console: INFO and above only
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # File: everything including DEBUG
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(
        log_dir, f"ids_log_{datetime.now().strftime('%Y%m%d')}.txt"
    )
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger