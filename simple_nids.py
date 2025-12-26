import psutil
import time
import json
from collections import defaultdict
from datetime import datetime

# config
THRESHOLD_PORTS = 5      # if they hit >5 ports, its probably a scan
WINDOW_SECONDS = 10      # check within 10 seconds
CHECK_INTERVAL = 0.5     # scanning fast so i don't miss anything

class NetworkDetector:
    def __init__(self):
        # storing hits like: { ip: [ {time: 123, port: 80}, ... ] }
        self.scan_history = defaultdict(list)
        self.alerted_ips = [] # keep track of IPs i've already caught

    def get_connections(self):
        # takes a snapshot of current traffic
        try:
            # specifically looking for IPv4 TCP connections
            # psutil is kinda basic but it works without raw sockets
            connections = psutil.net_connections(kind='inet')
            return connections
        except psutil.AccessDenied:
            return [] # usually happens if i forget sudo

    def analyze_traffic(self):
        print(f"[*] NIDS is live. watching for >{THRESHOLD_PORTS} port hits in {WINDOW_SECONDS}s...")
        
        try:
            while True:
                current_time = time.time()
                connections = self.get_connections()

                for conn in connections:
                    # conn.raddr is the remote address (the attacker)
                    # if it's None, it's just a local listener so ignore it
                    
                    if conn.raddr: 
                        remote_ip = conn.raddr.ip
                        local_port = conn.laddr.port
                        
                        # add to history
                        self.scan_history[remote_ip].append({
                            "time": current_time,
                            "port": local_port
                        })

                # run the logic to check for scans
                self.check_for_scans(current_time)
                
                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n[*] stopping NIDS.")

    def check_for_scans(self, current_time):
        # goes through history and checks if one IP is hitting too many ports
        for ip, hits in list(self.scan_history.items()):
            # 1. clean up old data (sliding window logic)
            # if the hit was too long ago, throw it out
            valid_hits = [h for h in hits if (current_time - h['time']) < WINDOW_SECONDS]
            self.scan_history[ip] = valid_hits

            # 2. count unique ports
            # hitting port 80 five times is normal. hitting 80, 22, 443, 21 is a scan.
            unique_ports = {h['port'] for h in valid_hits}

            # 3. trigger alert
            if len(unique_ports) >= THRESHOLD_PORTS:
                # check if i already alerted so i don't spam the terminal
                if ip not in self.alerted_ips:
                    self.alert(ip, list(unique_ports))
                    self.alerted_ips.append(ip) 
            
            # if they stop scanning, remove from ignored list so we can catch them again later
            if len(valid_hits) == 0 and ip in self.alerted_ips:
                self.alerted_ips.remove(ip)

    def alert(self, ip, ports):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "type": "PORT_SCAN",
            "source_ip": ip,
            "ports": ports,
            "msg": f"IP {ip} is noisy - accessed {len(ports)} ports in < {WINDOW_SECONDS}s"
        }
        print(json.dumps(log_entry, indent=4))

if __name__ == "__main__":
    nids = NetworkDetector()
    nids.analyze_traffic()