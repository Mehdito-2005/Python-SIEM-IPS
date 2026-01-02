# 🛡️ ClearData SIEM

**Lightweight Security Information & Event Management for Linux**

ClearData is a custom-built, lightweight **SIEM (Security Information & Event Management)** suite designed for Linux environments. It combines **File Integrity Monitoring (FIM)**, **Network Intrusion Detection (NIDS)**, and **Log Analysis (HIDS)** into a single real-time security dashboard.

Unlike purely passive monitoring tools, ClearData includes an **Active Intrusion Prevention System (IPS)** that can automatically revert unauthorized file changes and block malicious IP addresses using the system firewall (`ufw`).

---

## ✨ Key Features

### 🖥️ Centralized Security Dashboard

* Real-time web interface built with **Flask**
* Live counters for:

  * 🚨 Critical threats
  * ⚠️ Warnings
  * ℹ️ Informational events
* Auto-refreshes every **2 seconds**

---

### 📂 File Integrity Monitoring (FIM) + Active IPS

* Continuously monitors critical files (e.g. `secret_passwords.txt`)
* Detects unauthorized file changes using hash comparison
* **Auto-Revert:**

  * If a change is not authorized, the file is automatically restored from a secure backup

---

### 🌐 Network Intrusion Detection System (NIDS)

* Detects **port scanning behavior** (e.g. Nmap scans)
* Flags IP addresses that access **more than 5 unique ports within 10 seconds**
* Generates real-time alerts in the dashboard

---

### 🔐 Log Analysis (SIEM / HIDS)

* Monitors Linux authentication logs (`/var/log/auth.log`)
* Detects:

  * SSH brute-force attempts
* **Auto-Ban:**

  * Automatically blocks attacker IPs via `ufw` after **3 failed login attempts**

---

## 🧰 System Requirements

| Requirement | Details                                               |
| ----------- | ----------------------------------------------------- |
| OS          | Linux (Ubuntu / Mint / Kali recommended)              |
| Python      | Python 3.x                                            |
| Permissions | Root / sudo (required for firewall & packet sniffing) |
| Firewall    | `ufw`                                                 |

---

## 🛠️ Installation

### 1️⃣ Install Dependencies

```bash
sudo apt update
sudo apt install ufw
pip3 install flask psutil
```

---

### 2️⃣ Initialize the Database

Creates the SQLite database (`siem_events.db`) used to store alerts and logs.

```bash
python3 setup_db.py
```

---

## 🚦 Usage

### 🔘 One-Click Launcher (Recommended)

Runs the **dashboard and all monitoring modules** simultaneously.

```bash
sudo python3 launcher.py
```

**Dashboard:**
Open your browser at:

```
http://127.0.0.1:5000
```

**Default Login:**

```
admin123
```

**Stopping the system:**
Press `Ctrl + C` in the terminal to terminate all background processes.

---



---

## 📁 Project Structure

```
ClearData-SIEM/
├── launcher.py        # Master launcher for all components
├── dashboard.py       # Flask-based web dashboard
├── simple_siem.py     # Log analysis (SSH brute-force detection)
├── simple_nids.py     # Network intrusion detection (port scanning)
├── simple_fim.py      # File integrity monitoring
├── simple_ips.py      # Active response engine (firewall banning)
├── setup_db.py        # Database initialization/reset
├── logger.py          # Shared SQLite logging utility
└── siem_events.db     # SQLite database (generated)
```

---

## 🧪 Testing the System

### ✅ Test 1: File Integrity Monitor (FIM)

Modify the monitored file manually:

```bash
echo "Malicious Payload" >> secret_passwords.txt
```

**Expected Result:**

* Change is detected immediately
* User is prompted for authorization
* If unauthorized → file is automatically reverted

---

### ✅ Test 2: Network Intrusion Detection (NIDS)

Simulate a port scan against your own machine:

```bash
nmap -sT -p 1-100 127.0.0.1
```

**Expected Result:**

* Port scan detected
* **CRITICAL alert** appears on the dashboard

---

### ✅ Test 3: Log Analysis & Active IPS (SSH Brute Force)

Simulate SSH login failures:

```bash
logger -t sshd "Failed password for invalid user badguy from 10.10.10.5 port 22 ssh2"
```

Run this command **three times**.

**Expected Result:**

* IP `10.10.10.5` is automatically blocked via `ufw`
* Alert logged in the dashboard

---

## ⚠️ Disclaimer

> This project is intended for **educational and research purposes only**.

ClearData actively modifies firewall rules and restores files automatically.
**Do not deploy on production systems** without careful review, as misconfiguration could result in:

* Accidental IP blocking
* Self-lockout from the system

Use responsibly.

---

## 📌 Future Improvements

* Role-based dashboard authentication
* Email / webhook alerting
* Rule customization via UI
* Support for additional log sources
* Dockerized deployment
