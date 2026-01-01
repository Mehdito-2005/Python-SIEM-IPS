import psutil
import time
from collections import defaultdict
from logger import log_event

# Configuration
THRESHOLD_PORTS = 5      
WINDOW_SECONDS = 10      
CHECK_INTERVAL = 0.5     

class NetworkDetector:
    def __init__(self):
        # Structure: { ip: [ {time: 123, port: 80}, ... ] }
        self.scan_history = defaultdict(list)
        self.alerted_ips = [] 

    def get_connections(self):
        try:
            # Snapshot of current IPv4 TCP connections
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return [] # Requires sudo/root privileges

    def analyze_traffic(self):
        print(f"[*] NIDS is live. Threshold: >{THRESHOLD_PORTS} ports in {WINDOW_SECONDS}s")
        
        try:
            while True:
                current_time = time.time()
                connections = self.get_connections()

                for conn in connections:
                    # Filter for remote connections (raddr)
                    if conn.raddr: 
                        remote_ip = conn.raddr.ip
                        local_port = conn.laddr.port
                        
                        self.scan_history[remote_ip].append({
                            "time": current_time,
                            "port": local_port
                        })

                self.check_for_scans(current_time)
                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n[*] Stopping NIDS.")

    def check_for_scans(self, current_time):
        for ip, hits in list(self.scan_history.items()):
            # 1. Sliding Window: Remove hits older than WINDOW_SECONDS
            valid_hits = [h for h in hits if (current_time - h['time']) < WINDOW_SECONDS]
            self.scan_history[ip] = valid_hits

            # 2. Count Unique Ports (Port Scan Detection)
            unique_ports = {h['port'] for h in valid_hits}

            # 3. Trigger Alert
            if len(unique_ports) >= THRESHOLD_PORTS:
                if ip not in self.alerted_ips:
                    self.alert(ip, list(unique_ports))
                    self.alerted_ips.append(ip) 
            
            # Reset alert state if activity stops
            if len(valid_hits) == 0 and ip in self.alerted_ips:
                self.alerted_ips.remove(ip)

    def alert(self, ip, ports):
        msg = f"Source {ip} accessed {len(ports)} distinct ports in < {WINDOW_SECONDS}s"
        log_event("CRITICAL", "PORT_SCAN", ip, msg)

if __name__ == "__main__":
    nids = NetworkDetector()
    nids.analyze_traffic()