import time
import re
import json
import subprocess
from collections import defaultdict
from datetime import datetime

# config
LOG_FILE = "/var/log/auth.log"  # where linux stores the ssh logs
THRESHOLD = 3                   # max fails allowed before ban
WINDOW = 60                     # check within 60 seconds

class LogMonitor:
    def __init__(self):
        # keeps track of failed logins -> { ip: [time1, time2] }
        self.failed_logins = defaultdict(list)

    def follow(self, filename):
        # basically 'tail -f' in python
        # reads the file as it grows
        try:
            with open(filename, "r") as f:
                f.seek(0, 2) # go to the end of the file so we don't parse old stuff
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line
        except PermissionError:
            print(f"[!] forgot sudo... can't read {filename}")
            exit()

    def parse_log(self, line):
        # using regex to grab the attacker's IP and username
        ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        user_match = re.search(r"for (?:invalid user )?(\w+)", line)
        
        if ip_match and user_match:
            return user_match.group(1), ip_match.group(1)
        return None, None

    def ban_ip(self, ip_address):
        # safety check: dont ban localhost lol
        if ip_address == "127.0.0.1": 
            print(f"    [!] detected localhost. skipping ban.")
            return

        print(f"    [!!!] BANNING IP: {ip_address} (calling ufw)")
        try:
            # this runs the actual linux command to block them
            subprocess.run(["ufw", "deny", "from", ip_address], check=True)
            print(f"    [✓] IP {ip_address} is blocked.")
        except Exception as e:
            print(f"    [X] command failed: {e}")

    def monitor(self):
        print(f"[*] SIEM running... watching {LOG_FILE}")
        
        for line in self.follow(LOG_FILE):
            username, ip = self.parse_log(line)
            
            if username and ip:
                current_time = time.time()
                self.failed_logins[ip].append(current_time)
                
                print(f"    [!] failed login for {username} from {ip}")
                self.check_alert(username, ip, current_time)

    def check_alert(self, username, ip, current_time):
        # remove old fails that are outside the time window
        timestamps = self.failed_logins[ip]
        valid_timestamps = [t for t in timestamps if (current_time - t) < WINDOW]
        self.failed_logins[ip] = valid_timestamps

        # if they fail too many times, drop the hammer
        if len(valid_timestamps) >= THRESHOLD:
            self.alert(username, ip, len(valid_timestamps))
            self.ban_ip(ip) 
            self.failed_logins[ip] = [] # reset count so we don't spam bans

    def alert(self, username, ip, count):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "type": "BRUTE_FORCE",
            "user": username,
            "ip": ip,
            "msg": f"User failed {count} times in < {WINDOW}s. Banning."
        }
        print("\n" + json.dumps(log_entry, indent=4) + "\n")

if __name__ == "__main__":
    siem = LogMonitor()
    siem.monitor()