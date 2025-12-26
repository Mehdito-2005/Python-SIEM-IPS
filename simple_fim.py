import hashlib
import time
import os
import json
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, files_to_monitor):
        self.files_to_monitor = files_to_monitor
        self.baseline = {}

    def calculate_hash(self, file_path):
        """
        Calculates the SHA-256 hash. 
        Using SHA256 because MD5 is basically broken now lol.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Reading 4k bytes at a time so I don't crash my RAM with massive files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None

    def create_baseline(self):
        """
        Saves the 'clean' state of the files before monitoring starts.
        """
        print(f"[*] Calculating hashes for {len(self.files_to_monitor)} files...")
        for file_path in self.files_to_monitor:
            file_hash = self.calculate_hash(file_path)
            if file_hash:
                self.baseline[file_path] = file_hash
                print(f"    [+] Saved baseline for: {file_path}")
            else:
                print(f"    [!] Weird, couldn't find {file_path}. Skipping.")
        print("[*] Baseline ready. Don't touch the files now!\n")

    def monitor(self, interval=5):
        """
        Infinite loop that checks the files every few seconds.
        """
        print(f"[*] Watching files... scanning every {interval} seconds.")
        print("    (Hit Ctrl+C to kill it)")
        
        try:
            while True:
                time.sleep(interval)
                
                for file_path in self.files_to_monitor:
                    current_hash = self.calculate_hash(file_path)
                    original_hash = self.baseline.get(file_path)

                    # Scenario 1: Hash mismatch (Modification detected)
                    if current_hash and original_hash and current_hash != original_hash:
                        self.alert(file_path, "FILE_MODIFIED", f"Hash changed! old={original_hash[:8]}... new={current_hash[:8]}...")
                        
                        # Update the baseline so it doesn't spam me with the same alert 100 times
                        self.baseline[file_path] = current_hash

                    # Scenario 2: File is gone (Deletion detected)
                    elif not current_hash and original_hash:
                        self.alert(file_path, "FILE_DELETED", "File just vanished from disk.")
                        del self.baseline[file_path]

        except KeyboardInterrupt:
            print("\n[*] Stopping monitor. Bye.")

    def alert(self, target, alert_type, message):
        """
        Prints the alert in JSON format so it looks professional/parsable.
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "alert_type": alert_type,
            "target": target,
            "message": message
        }
        # dumping to json makes it easier to ingest into Splunk/ELK later
        print(json.dumps(log_entry, indent=4))

if __name__ == "__main__":
    # 1. Setup a dummy file to test the hashing
    test_file = "secret_passwords.txt"
    with open(test_file, "w") as f:
        f.write("SuperSecretPassword123")

    # 2. List of files to watch
    # In a real deployment, I'd point this to /etc/passwd or /etc/shadow
    files = [test_file]
    
    # 3. Fire up the monitor
    fim = FileIntegrityMonitor(files)
    fim.create_baseline()
    fim.monitor(interval=3)