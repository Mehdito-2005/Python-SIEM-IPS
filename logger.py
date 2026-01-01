import sqlite3
from datetime import datetime

DB_NAME = "siem_events.db"

def init_db():
    """Creates the database table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            level TEXT,
            type TEXT,
            source TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print(f"[*] Database {DB_NAME} initialized.")

def log_event(level, alert_type, source, message):
    """Saves an alert to the database."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute("INSERT INTO alerts (timestamp, level, type, source, message) VALUES (?, ?, ?, ?, ?)",
              (timestamp, level, alert_type, source, message))
    
    conn.commit()
    conn.close()
    # Still print to terminal so you can see it happening
    print(f"[{level}] {alert_type}: {message}")

# Run this file once directly to create the DB
if __name__ == "__main__":
    init_db()