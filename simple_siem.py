import time
import re
import subprocess
import os
from collections import defaultdict
from logger import log_event

# Configuration
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 3
WINDOW = 60

class LogMonitor:
    """
    Real-time log analyzer that detects SSH brute-force attacks 
    and triggers automated responses.
    """
    def __init__(self):
        # Tracking structure: { ip_address: [timestamp1, timestamp2] }
        self.failed_logins = defaultdict(list)

    def follow(self, filename):
        """
        Generator that mimics 'tail -f', yielding new lines as they are written.
        """
        try:
            with open(filename, "r") as f:
                f.seek(0, 2) # Move file pointer to the end
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line
        except PermissionError:
            print(f"[!] Error: Permission denied reading {filename}. Try running with sudo.")
            exit(1)

    def parse_log(self, line):
        """
        Extracts the username and IP address from a log line using Regex.
        """
        ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        user_match = re.search(r"for (?:invalid user )?(\w+)", line)
        
        if ip_match and user_match:
            return user_match.group(1), ip_match.group(1)
        return None, None

    def ban_ip(self, ip_address):
        """
        Executes a UFW command to block the malicious IP at the firewall level.
        """
        # Whitelist localhost to prevent accidental self-lockout
        if ip_address == "127.0.0.1": 
            return

        print(f"    [!!!] BANNING IP: {ip_address}")
        try:
            # Suppress stdout to keep the terminal clean
            subprocess.run(["ufw", "deny", "from", ip_address], check=True, stdout=subprocess.DEVNULL)
            print(f"    [✓] Firewall rule updated: Blocked {ip_address}")
        except Exception as e:
            print(f"    [X] Firewall command failed: {e}")

    def monitor(self):
        print(f"[*] SIEM Log Monitor Active. Watching: {LOG_FILE}")
        
        for line in self.follow(LOG_FILE):
            # Only process relevant authentication failures
            if "Failed password" in line:
                username, ip = self.parse_log(line)
                
                if username and ip:
                    current_time = time.time()
                    self.failed_logins[ip].append(current_time)
                    
                    # Log event to database
                    log_event("Warning", "FAILED_LOGIN", ip, f"Failed login for {username}")
                    print(f"    [!] Detected failed login: {username}@{ip}")
                    
                    self.check_alert(username, ip, current_time)

    def check_alert(self, username, ip, current_time):
        """
        Validates if the failure count exceeds the threshold within the time window.
        """
        # Sliding Window: Retain only timestamps within the valid window
        timestamps = self.failed_logins[ip]
        valid_timestamps = [t for t in timestamps if (current_time - t) < WINDOW]
        self.failed_logins[ip] = valid_timestamps

        # Check Threshold
        if len(valid_timestamps) >= THRESHOLD:
            self.alert(username, ip, len(valid_timestamps))
            self.ban_ip(ip) 
            self.failed_logins[ip] = [] # Reset counter after action to prevent redundant bans

    def alert(self, username, ip, count):
        msg = f"Brute Force Detected: {count} failed attempts in < {WINDOW}s."
        log_event("CRITICAL", "BRUTE_FORCE", ip, msg)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Error: This script requires root privileges to read system logs.")
        exit(1)

    siem = LogMonitor()
    siem.monitor()