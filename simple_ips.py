import sqlite3
import time
import os
import subprocess
from logger import log_event

# Configuration
DB_NAME = "siem_events.db"
BLOCKED_IPS = set()

def block_ip(ip_address):
    """
    Executes a system-level firewall ban using UFW.
    """
    if ip_address in BLOCKED_IPS:
        return

    print(f"[+] 🛡️  IPS ENGAGED: Blocking {ip_address}...")
    
    try:
        # 1. Execute the blocking command (UFW)
        # Note: 'prepend' ensures the deny rule is at the top of the list
        cmd = f"ufw insert 1 deny from {ip_address} to any"
        subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL)
        
        # 2. Log the action to the dashboard
        log_event("Warning", "IPS_BLOCK", "IPS", f"Blocked malicious IP: {ip_address}")
        
        BLOCKED_IPS.add(ip_address)
        
    except Exception as e:
        print(f"    [!] IPS Failed to block {ip_address}: {e}")

def scan_threats():
    """
    Continuously monitors the database for Critical threats and triggers blocks.
    """
    print("[*] IPS Engine Active. Monitoring for threats...")
    
    while True:
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            # Query for recent events where the type contains 'CRITICAL'
            # We look at the last 10 events to ensure rapid response
            cursor.execute("SELECT source FROM events WHERE type LIKE '%CRITICAL%' ORDER BY id DESC LIMIT 10")
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                suspect_ip = row[0]
                
                # Basic validation: ensure source looks like an IP and isn't local
                if suspect_ip not in BLOCKED_IPS and suspect_ip not in ["127.0.0.1", "localhost", "FIM"]:
                    # Additional check: verify it's a valid IP string roughly
                    if len(suspect_ip.split('.')) == 4:
                        block_ip(suspect_ip)
            
        except Exception as e:
            print(f"[!] IPS Loop Error: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    # Ensure root privileges for firewall modification
    if os.geteuid() != 0:
        print("[!] Error: IPS requires root privileges (sudo) to manage the firewall.")
        exit(1)
        
    scan_threats()