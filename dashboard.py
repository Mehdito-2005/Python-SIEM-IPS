from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# --- CONFIGURATION ---
DB_NAME = "siem_events.db"
app.secret_key = "CHANGE_THIS_TO_RANDOM_BYTES" # Required for session security
ADMIN_PASSWORD = "admin123" 

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid Password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch recent events
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    
    # Calculate stats using partial matching to catch composite types (e.g., "PORT_SCAN (CRITICAL)")
    cursor.execute("SELECT COUNT(*) FROM events WHERE type LIKE '%Critical%' OR type LIKE '%CRITICAL%'")
    critical_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM events WHERE type LIKE '%Warning%'")
    warning_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM events WHERE type LIKE '%Info%'")
    info_count = cursor.fetchone()[0]
    
    conn.close()
    
    events = [dict(row) for row in rows]
    
    return jsonify({
        "events": events,
        "stats": {
            "critical": critical_count,
            "warning": warning_count,
            "info": info_count
        }
    })

if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        print(f"[!] Database {DB_NAME} not found. Run setup_db.py first.")
        
    app.run(host='0.0.0.0', debug=True, port=5000)