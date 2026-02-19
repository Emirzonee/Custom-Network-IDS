# Custom Network IDS/IPS

A custom-built, lightweight Network Intrusion Detection System (IDS) developed in Python. This tool captures network traffic at Layer 2 using `scapy` and performs statistical behavioral analysis to detect anomalies such as SYN Floods and Port Scans in real-time.

## Architecture & Core Technologies
* **Core:** Python 3, Object-Oriented Programming (OOP)
* **Network Analysis:** `scapy` for real-time packet sniffing and dissection.
* **Code Quality:** Strict Type Hinting applied across all modules.
* **Testing:** Automated unit testing implemented with `pytest` and Mocking techniques.
* **Auditing:** Professional `logging` module implementation with separate file and console handlers.

## Detection Engine
The system moves beyond simple signature matching by implementing a time-window-based statistical algorithm. It tracks connection initiation requests (TCP SYN) from specific source IP addresses and triggers `[CRITICAL]` alerts if the threshold is exceeded within the defined time frame, effectively mitigating DDoS attempts and network reconnaissance.

## Installation

1. Clone the repository:
```bash
git clone [https://github.com/Emirzonee/Custom-Network-IDS.git](https://github.com/Emirzonee/Custom-Network-IDS.git)
cd Custom-Network-IDS

2. Initialize the virtual environment:
```bash
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

*Note: Requires administrative/root privileges to bind to the network interface (Npcap/WinPcap must be installed on Windows).*

Execute the main detection engine:
```bash
python main.py
```

## Testing

The project includes automated unit tests to validate the statistical analysis engine and threshold triggers. Run the test suite using:
```bash
python -m pytest
```

## License
MIT License