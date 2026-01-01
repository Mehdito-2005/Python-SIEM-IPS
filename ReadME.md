# EagleEye: Custom Host-Based SIEM & Dashboard
**A full-stack security monitoring system with real-time web visualization and active defense.**

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Flask](https://img.shields.io/badge/Frontend-Flask-lightgrey?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-blue?style=flat&logo=sqlite)
![Security](https://img.shields.io/badge/Focus-Blue_Team-red?style=flat&logo=security)

## 📌 Project Overview
EagleEye is a modular **Security Information and Event Management (SIEM)** system built from scratch. It centralizes logs into a database, visualizes threats on a real-time web dashboard, and performs **Active Defense** measures.

It consists of three core components:
1.  **The Agents (Sensors):** Python scripts that monitor File Integrity, Network Traffic, and Auth Logs.
2.  **The Brain (Logger):** A centralized SQLite database that ingests alerts from all agents.
3.  **The Eyes (Dashboard):** A Flask-based web interface that auto-refreshes to show attacks as they happen.

---

## 🛠️ Architecture

### 1. The Dashboard (Web UI)
* **File:** `dashboard.py`
* **Tech:** Flask, HTML/CSS, SQLite.
* **Function:** Reads the database every 5 seconds and displays a color-coded threat table (Red for Critical, Green for Info).

### 2. File Integrity Monitor (FIM) with Rollback
* **File:** `simple_fim.py`
* **Function:** Calculates SHA-256 hashes of sensitive files.
* **Active Defense:** If a file is modified (hash mismatch), it triggers an **Automated Rollback Sequence**, prompting the user to restore the file from a secure backup immediately.

### 3. Network Intrusion Detector (NIDS)
* **File:** `simple_nids.py`
* **Function:** Detects rapid port scanning using heuristic analysis (sliding window logic) to identify reconnaissance attempts.

### 4. Automated IPS
* **File:** `simple_siem.py`
* **Function:** Parses system logs for brute-force attempts and automatically bans IPs via UFW.

---

## 🚀 Installation & Usage

### Prerequisites
* Python 3.x
* Flask (`pip install flask`)

### Running the System
First, run the logger to initialize the database. Then, use separate terminals to run the dashboard and the agents.

```bash
# 1. Initialize the Database
python3 logger.py

# 2. Start the Dashboard (Terminal 1)
python3 dashboard.py
# (Access the UI at [http://127.0.0.1:5000](http://127.0.0.1:5000))

# 3. Start the Agent (Terminal 2)
python3 simple_fim.py