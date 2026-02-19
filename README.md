# Custom Network IDS/IPS

## Project Overview

A network intrusion detection and prevention system that captures live traffic at Layer 2, applies a sliding time-window algorithm to identify SYN Flood and Port Scan patterns, and automatically creates Windows Firewall rules to block confirmed attackers. Detected events are stored in a local SQLite database and displayed through a Streamlit dashboard for real-time monitoring.

---

## Why I Built This

I wanted to understand what actually happens at the packet level when an attack hits a machine — not just read about it. Most security tools are black boxes; building one from scratch forced me to understand how SYN Flood works at the TCP handshake level, how to distinguish attack traffic from normal traffic statistically, and how to translate a detection into an actual system-level response via the Windows Firewall.

---

## Core Tech Stack

- Python 3.10+
- `scapy` — raw packet capture and parsing
- `streamlit` — web dashboard
- `plotly` — attack intensity charts
- `sqlite3` — persistent attack logging (standard library)
- `pytest` — unit tests with mock packet injection

---

## Key Engineering Decisions

**Sliding time window over fixed counters**

A fixed counter (e.g. "more than 20 SYN packets total") would flag a host after a slow scan spread over hours, or miss a fast burst that resets the counter. I implemented a sliding window: each SYN packet timestamp is stored per source IP, and on every new packet, timestamps older than `TIME_WINDOW` seconds are pruned. Only the count within the active window is compared against the threshold. This makes detection sensitive to burst rate rather than total volume.

**Tracker reset after detection**

After an attack is logged, the SYN tracker for that IP is cleared. Without this, every subsequent packet from the same source would keep triggering alerts for the same burst, flooding both the logs and the database with duplicate records. The reset means each burst generates exactly one alert.

**Windows Firewall via `netsh` subprocess**

Rather than integrating a third-party firewall library, I used `subprocess` to call `netsh advfirewall` directly. This keeps the dependency count low and uses the same mechanism a network administrator would use manually. The trade-off is that it requires administrator privileges and is Windows-only.

**IDS and IPS as separate concerns**

The detection engine (`sniffer.py`) and the blocking action (`app.py`) are intentionally decoupled. The sniffer detects and logs; the dashboard lets a human decide which IPs to block. This avoids automatic false-positive blocking while still enabling one-click mitigation from the UI.

---

## Challenges & Lessons

**Raw packet capture requires administrator privileges**

The first run failed silently — scapy captured zero packets without any error message. After investigation, the issue was that raw socket access on Windows requires elevated privileges. Running the terminal as administrator fixed it. I added a note in the startup log to make this requirement visible immediately.

**Mocking the database in tests**

The initial test suite instantiated a real `DatabaseManager`, which created an actual SQLite file on disk during every test run. I patched `DatabaseManager` with `unittest.mock.patch` so tests run fully in memory with no filesystem side effects. This also made the tests faster and isolated from database-related failures.

**Separating detection logic from packet parsing**

The first version put everything inside `packet_handler()` — parsing, analysis, and logging in one block. Splitting packet parsing into `packet_handler()` and detection logic into `analyze_packet()` made the code testable: I can now inject synthetic Scapy packets directly into `analyze_packet()` in tests without needing a live network interface.

---

## How to Run

**Requirements: Run terminal as Administrator (raw packet capture needs it)**

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Start the IDS engine** — Terminal 1
```bash
python main.py
```

**3. Start the dashboard** — Terminal 2
```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

**4. Run tests**
```bash
pytest tests/ -v
```

---

## Project Structure

```
.
├── src/
│   ├── sniffer.py          # Packet capture and SYN Flood detection
│   ├── database_manager.py # SQLite attack logging
│   └── logger.py           # Dual-output logger (console + file)
├── tests/
│   └── test_sniffer.py     # Unit tests with mock packet injection
├── logs/                   # Auto-created: attack DB and log files
├── app.py                  # Streamlit dashboard + firewall blocking
├── main.py                 # IDS engine entry point
├── config.yaml             # Detection thresholds and settings
└── requirements.txt
```

---

## License

MIT — Emircan Bingöl, 2026