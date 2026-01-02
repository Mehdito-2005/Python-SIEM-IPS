import sqlite3
from datetime import datetime

DB_NAME = "siem_events.db"

def log_event(level, type, source, message):
    """
    Unified logging interface for all system modules.
    Inserts structured events into the central SQLite database.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format event type to include severity level
        full_type = f"{type} ({level})"
        
        cursor.execute("INSERT INTO events (timestamp, source, type, message) VALUES (?, ?, ?, ?)",
                       (timestamp, source, full_type, message))
        
        conn.commit()
        conn.close()
        
        # Output to console for real-time monitoring
        print(f"    [LOGGED] {timestamp} - {source} - {full_type}")
        
    except Exception as e:
        print(f"[!] Database Error in logger: {e}")