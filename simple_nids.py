import psutil
import time
from collections import defaultdict
from logger import log_event
import os

# Configuration
THRESHOLD_PORTS = 5      
WINDOW_SECONDS = 10      
CHECK_INTERVAL = 0.5     

class NetworkDetector:
    """
    Monitors active TCP connections to detect Port Scanning activities.
    """
    def __init__(self):
        # Scan History: { ip: [ {time: 123, port: 80}, ... ] }
        self.scan_history = defaultdict(list)
        self.alerted_ips = [] 

    def get_connections(self):
        """Retrieves current IPv4 TCP connections (Requires Root)."""
        try:
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return []

    def analyze_traffic(self):
        print(f"[*] NIDS Active. Threshold: >{THRESHOLD_PORTS} ports in {WINDOW_SECONDS}s")
        
        try:
            while True:
                current_time = time.time()
                connections = self.get_connections()

                for conn in connections:
                    # Filter for remote connections where IP is established
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
            # 1. Prune old history based on sliding window
            valid_hits = [h for h in hits if (current_time - h['time']) < WINDOW_SECONDS]
            self.scan_history[ip] = valid_hits

            # 2. Count distinct ports accessed
            unique_ports = {h['port'] for h in valid_hits}

            # 3. Trigger Alert
            if len(unique_ports) >= THRESHOLD_PORTS:
                if ip not in self.alerted_ips:
                    self.alert(ip, list(unique_ports))
                    self.alerted_ips.append(ip) 
            
            # Reset alert state if activity ceases
            if len(valid_hits) == 0 and ip in self.alerted_ips:
                self.alerted_ips.remove(ip)

    def alert(self, ip, ports):
        msg = f"Port Scan Detected: Accessed {len(ports)} ports in < {WINDOW_SECONDS}s"
        print(f"    [!] CRITICAL: {msg} from {ip}")
        # Log as CRITICAL so the IPS picks it up
        log_event("CRITICAL", "PORT_SCAN", ip, msg)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Error: NIDS requires root (sudo) to see network traffic.")
        exit(1)
        
    nids = NetworkDetector()
    nids.analyze_traffic()