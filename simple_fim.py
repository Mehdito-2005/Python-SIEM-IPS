import time
import hashlib
import os
import shutil
from logger import log_event

# --- CONFIGURATION ---
FILES_TO_MONITOR = ["secret_passwords.txt"]

def calculate_hash(filepath):
    """Computes the SHA-256 hash of a file."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"[!] Read Error: {e}")
        return None

def init_file(filepath):
    """Initializes the monitored file and creates a baseline backup."""
    if not os.path.exists(filepath):
        print(f"[+] Creating baseline file: {filepath}")
        with open(filepath, 'w') as f:
            f.write("Initial Secure Content")
    
    update_backup(filepath)

def update_backup(filepath):
    """Updates the secure backup copy."""
    shutil.copy(filepath, filepath + ".bak")

def restore_backup(filepath):
    """Restores the file from the last known good backup."""
    backup_name = filepath + ".bak"
    if os.path.exists(backup_name):
        shutil.copy(backup_name, filepath)
        print(f"    [↺] RESTORE: Reverted {filepath} from backup.")
    else:
        print(f"    [!] Error: No backup found.")

def start_monitoring():
    print(f"[*] FIM Active. Monitoring: {FILES_TO_MONITOR}")
    
    # Initialize baseline hashes
    file_hashes = {}
    for file in FILES_TO_MONITOR:
        init_file(file)
        file_hashes[file] = calculate_hash(file)

    print("[*] Monitoring loop started...")

    while True:
        time.sleep(2)
        
        for file in FILES_TO_MONITOR:
            new_hash = calculate_hash(file)
            
            # Case 1: File Deletion
            if new_hash is None and file_hashes[file] is not None:
                print(f"\n[!] ALERT: {file} DELETED")
                log_event("Critical", "FIM_DELETE", "FIM", f"File DELETED: {file}")
                
                # Interactive Restore (Warning: Blocking I/O)
                choice = input(f"    ⚠️  Restore from backup? (y/n): ").lower()
                if choice == 'y':
                    restore_backup(file)
                else:
                    file_hashes[file] = None # Accept deletion
            
            # Case 2: File Modification
            elif new_hash != file_hashes[file]:
                print(f"\n[!] ALERT: {file} MODIFIED")
                
                # Interactive Authorization (Warning: Blocking I/O)
                choice = input(f"    ❓ Authorize change? (y/n): ").lower()
                
                if choice == 'y':
                    print("    [✓] Change Authorized. Updating baseline.")
                    log_event("Info", "FIM_UPDATE", "FIM", f"Authorized change: {file}")
                    update_backup(file)
                    file_hashes[file] = new_hash
                else:
                    print("    [X] UNAUTHORIZED. Reverting...")
                    log_event("Critical", "FIM_REVERT", "FIM", f"Reverted unauthorized change: {file}")
                    restore_backup(file)

if __name__ == "__main__":
    start_monitoring()