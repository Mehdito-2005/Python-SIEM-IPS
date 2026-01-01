import subprocess
import time
import sys
import os

# List of scripts to run
# specific filenames you are using:
SCRIPTS = [
    "dashboard.py",
    "simple_fim.py",
    "simple_nids.py"
    # "simple_siem.py"  <-- Uncomment this if you are using the IPS script too
]

processes = []

def start_processes():
    print(f"[*] Starting EagleEye System...")
    print(f"[*] Interpreter: {sys.executable}")
    
    for script in SCRIPTS:
        if not os.path.exists(script):
            print(f"[!] Error: {script} not found. Skipping.")
            continue
            
        print(f"    [+] Launching {script}...")
        
        # subprocess.Popen runs the script in the background
        # sys.executable ensures we use the same 'venv' python
        p = subprocess.Popen([sys.executable, script])
        processes.append(p)
        
    print("[*] All systems operational. Press Ctrl+C to stop.\n")

def stop_processes():
    print("\n[*] Shutting down EagleEye...")
    for p in processes:
        try:
            p.terminate() # Sends a polite signal to stop
        except Exception as e:
            print(f"    [!] Error killing process: {e}")
    print("[*] Shutdown complete.")

if __name__ == "__main__":
    try:
        start_processes()
        
        # Keep the main script alive so we can catch Ctrl+C
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        stop_processes()