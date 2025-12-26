# Implementation Plan - Major Project Upgrade

## Goal
Upgrade the Cybersecurity IDS project to "Major Project" standards by adding:
1.  **Real-Time Packet Sniffing**: Capture real network traffic using `scapy` instead of relying solely on simulation.
2.  **Database Integration**: Persist logs and blocked IPs using SQLite so data isn't lost on restart.

## User Review Required
> [!IMPORTANT]
> **Npcap Requirement**: For real packet sniffing to work on Windows, you must have [Npcap](https://npcap.com/) installed with "Install Npcap in WinPcap API-compatible Mode" checked. If not installed, the app will fall back to simulation mode.

## Proposed Changes

### 1. Database Integration (`database.py` & `app.py`)
We will use **MySQL** for robust data persistence.

#### [MODIFY] [requirements.txt](file:///c:/Users/GOWTHAM/OneDrive/Desktop/Pro/cyber_ids_system/requirements.txt)
-   Add `mysql-connector-python` dependency.

#### [NEW] [database.py](file:///c:/Users/GOWTHAM/OneDrive/Desktop/Pro/cyber_ids_system/database.py)
-   **Configuration**: Connect to local MySQL server (default: `root`, no password, localhost). *User will need to update credentials if different.*
-   `init_db()`: Create database `cyber_ids` and tables `traffic_logs`, `blocked_ips` if they don't exist.
-   `log_traffic(data)`: Insert new traffic entry.
-   `block_ip(ip)`: Add IP to blocklist.
-   `get_recent_logs(limit)`: Fetch logs for the dashboard.
-   `get_stats()`: Get total counts for the statistics panel.

#### [MODIFY] [app.py](file:///c:/Users/GOWTHAM/OneDrive/Desktop/Pro/cyber_ids_system/app.py)
-   Initialize DB on startup.
-   Replace in-memory lists (`traffic_logs`, `blocked_ips`) with DB calls.
-   Update API endpoints (`/api/traffic-monitor`, `/api/statistics`) to query the DB.

### 2. Real Packet Sniffing (`sniffer.py` & `app.py`)
We need a background thread to capture packets without freezing the Flask server.

#### [NEW] [sniffer.py](file:///c:/Users/GOWTHAM/OneDrive/Desktop/Pro/cyber_ids_system/sniffer.py)
-   Class `PacketSniffer`:
    -   Uses `scapy.sniff` to capture packets.
    -   Extracts `src_ip`, `dst_ip`, `protocol`, `size`.
    -   Calculates/Estimates features required by the ML model.
    -   Puts processed data into a thread-safe Queue.

#### [MODIFY] [app.py](file:///c:/Users/GOWTHAM/OneDrive/Desktop/Pro/cyber_ids_system/app.py)
-   Start `PacketSniffer` thread on app launch.
-   In `/api/traffic-monitor`:
    -   Check if there are real packets in the Queue.
    -   If yes, use them.
    -   If no (quiet network), fall back to `simulate_network_traffic()` to keep the dashboard alive.

## Verification Plan

### Automated Tests
-   Run `app.py` and verify `cyber_ids.db` is created.
-   Check if real local IP addresses appear in the dashboard.

### Manual Verification
-   Open Dashboard.
-   Generate some traffic (e.g., open a YouTube video or run `ping 8.8.8.8`).
-   Verify that the "Source IP" in the logs matches your local network (e.g., `192.168.x.x`).
-   Restart the app and verify that previous logs and blocked IPs are still there (Persistence).
