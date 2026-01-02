import sqlite3

def init_db():
    conn = sqlite3.connect("siem_events.db")
    cursor = conn.cursor()
    
    # Create the events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            type TEXT,
            message TEXT
        )
    """)
    
    # Inject one "Test" event so the dashboard isn't empty (which can sometimes cause bugs)
    cursor.execute("INSERT INTO events (timestamp, source, type, message) VALUES ('2026-01-01 12:00:00', 'SYSTEM', 'Info', 'SIEM Database Initialized')")
    
    conn.commit()
    conn.close()
    print("[+] Database 'siem_events.db' rebuilt successfully.")

if __name__ == "__main__":
    init_db()
