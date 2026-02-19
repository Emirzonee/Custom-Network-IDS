# Custom Network IDS/IPS

This repository contains a Python-based Network Intrusion Detection and Prevention System (IDS/IPS). The system captures network traffic at Layer 2, applies statistical analysis to identify anomalous connection patterns (such as SYN Floods and Port Scans), and provides active mitigation by automatically creating Windows Firewall rules to block malicious traffic. It also includes a web-based dashboard for real-time monitoring and an SQLite database for persistent logging.

## Features

* Layer-2 Packet Sniffing: Intercepts and dissects network traffic using Scapy.
* Anomaly Detection: Utilizes a time-window-based algorithm to identify abnormal connection rates.
* Active Threat Mitigation (IPS): Integrates directly with Windows Defender Firewall to block identified malicious IP addresses.
* Real-Time Dashboard: Provides a graphical interface built with Streamlit and Plotly for traffic visualization and threat monitoring.
* Audit Logging: Stores historical attack data in an SQLite database for later analysis.
* Automated Testing: Includes a test suite built with pytest to validate engine logic.

## Architecture and Technologies

* Core Language: Python 3
* Network Analysis: Scapy
* Frontend Interface: Streamlit, Plotly, Pandas
* Database: SQLite3
* OS Integration: Windows `netsh` utility

## Installation

1. Clone the repository:
```bash
git clone [https://github.com/Emirzonee/Custom-Network-IDS.git](https://github.com/Emirzonee/Custom-Network-IDS.git)
cd Custom-Network-IDS
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Note: Running the detection engine requires administrative privileges (Npcap/WinPcap must be installed on Windows). The IPS feature also requires administrative rights to modify Windows Firewall rules.

1. Start the main IDS engine:
```bash
python main.py
```

2. Launch the monitoring dashboard (in a separate terminal):
```bash
streamlit run app.py
```

## Testing

To run the unit tests and validate the statistical thresholds:
```bash
python -m pytest
```

## License
MIT License