import hashlib
import time
import os
import json
import shutil
from datetime import datetime
from logger import log_event

class FileIntegrityMonitor:
    def __init__(self, files_to_monitor):
        self.files_to_monitor = files_to_monitor
        self.baseline = {}
        self.backup_dir = "backups"
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None

    def create_baseline(self):
        print(f"[*] Creating baseline and backups for {len(self.files_to_monitor)} files...")
        for file_path in self.files_to_monitor:
            file_hash = self.calculate_hash(file_path)
            if file_hash:
                self.baseline[file_path] = file_hash
                # Create backup
                file_name = os.path.basename(file_path)
                backup_path = os.path.join(self.backup_dir, file_name)
                shutil.copy(file_path, backup_path)
                print(f"    [+] Backup created: {backup_path}")
            else:
                print(f"    [!] File {file_path} not found. Skipping.")
        print("[*] Baseline ready. Monitoring started.\n")

    def restore_file(self, file_path):
        file_name = os.path.basename(file_path)
        backup_path = os.path.join(self.backup_dir, file_name)
        try:
            shutil.copy(backup_path, file_path)
            print(f"    [+] Success: File restored from backup.")
            self.alert(file_path, "FILE_RESTORED", "User authorized rollback.")
        except Exception as e:
            print(f"    [!] Restore failed: {e}")

    def monitor(self, interval=3):
        print(f"[*] Watching files... scanning every {interval} seconds.")
        
        try:
            while True:
                time.sleep(interval)
                
                for file_path in self.files_to_monitor:
                    current_hash = self.calculate_hash(file_path)
                    original_hash = self.baseline.get(file_path)

                    # Scenario 1: Hash mismatch (Modification detected)
                    if current_hash and original_hash and current_hash != original_hash:
                        print(f"\n[!] ALERT: {file_path} has been modified!")
                        self.alert(file_path, "FILE_MODIFIED", f"Hash mismatch detected.")
                        
                        # PROMPT THE USER
                        response = input(f"    [?] Do you want to restore the original file? (y/n): ").lower()
                        
                        if response == 'y':
                            self.restore_file(file_path)
                            # After restore, hash matches baseline again, so no update needed
                        else:
                            print(f"    [+] Change authorized. Updating baseline.")
                            self.baseline[file_path] = current_hash
                            self.alert(file_path, "CHANGE_AUTHORIZED", "User allowed file modification.")

                    # Scenario 2: File is gone (Deletion detected)
                    elif not current_hash and original_hash:
                        print(f"\n[!] ALERT: {file_path} has been deleted!")
                        self.alert(file_path, "FILE_DELETED", "File vanished.")
                        
                        response = input(f"    [?] Do you want to recover the file? (y/n): ").lower()
                        
                        if response == 'y':
                            self.restore_file(file_path)
                        else:
                            print(f"    [+] Deletion authorized.")
                            del self.baseline[file_path]

        except KeyboardInterrupt:
            print("\n[*] Stopping monitor.")

    def alert(self, target, alert_type, message):
        log_event("CRITICAL", alert_type, target, message)

if __name__ == "__main__":
    # 1. Setup a dummy file
    test_file = "secret_passwords.txt"
    if not os.path.exists(test_file):
        with open(test_file, "w") as f:
            f.write("SuperSecretPassword123")

    # 2. Files to watch
    files = [test_file]
    
    # 3. Start Monitor
    fim = FileIntegrityMonitor(files)
    fim.create_baseline()
    fim.monitor(interval=3)