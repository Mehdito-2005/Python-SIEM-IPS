import subprocess
import time
import os
import signal
import sys

# Configuration: List of modules to execute
PROCESSES = [
    ["python3", "dashboard.py"],     
    ["python3", "simple_fim.py"],    
    ["python3", "simple_nids.py"],   
    ["python3", "simple_siem.py"],   
    ["python3", "simple_ips.py"]     
]

jobs = []

def cleanup(sig, frame):
    """Signal handler to terminate background processes gracefully."""
    print("\n\n[*] Shutting down SIEM Suite...")
    for process in jobs:
        print(f"    [-] Killing PID {process.pid}...")
        process.terminate()
    sys.exit(0)

def main():
    # Root privileges are required for raw socket access (NIDS) and log reading (SIEM)
    if os.geteuid() != 0:
        print("[!] Warning: This script should be run with 'sudo' for full functionality.")
        time.sleep(2)

    print(f"[*] Initializing SIEM Suite ({len(PROCESSES)} modules)...")
    
    # Register signal listener for Ctrl+C
    signal.signal(signal.SIGINT, cleanup)

    for script_cmd in PROCESSES:
        try:
            print(f"    [+] Launching: {' '.join(script_cmd)}")
            p = subprocess.Popen(script_cmd)
            jobs.append(p)
            time.sleep(1) # Short delay to prevent database locking contention on startup
        except Exception as e:
            print(f"    [!] Error starting {script_cmd}: {e}")

    print("\n[*] System Online. Dashboard accessible at http://127.0.0.1:5000")
    print("[*] Press Ctrl+C to stop all modules.\n")
    
    # Keep parent process alive to listen for signals
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()