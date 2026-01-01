from flask import Flask, render_template_string
import sqlite3

app = Flask(__name__)
DB_NAME = "siem_events.db"


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>EagleEye SIEM Dashboard</title>
    <meta http-equiv="refresh" content="5"> <style>
        body { font-family: monospace; background-color: #1e1e1e; color: #00ff00; padding: 20px; }
        h1 { border-bottom: 2px solid #00ff00; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #444; padding: 10px; text-align: left; }
        th { background-color: #333; }
        tr:nth-child(even) { background-color: #2a2a2a; }
        .CRITICAL { color: #ff3333; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🦅 EagleEye SIEM - Live Threat Feed</h1>
    <table>
        <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Level</th>
            <th>Type</th>
            <th>Source</th>
            <th>Message</th>
        </tr>
        {% for row in rows %}
        <tr class="{{ row[2] }}">
            <td>{{ row[0] }}</td>
            <td>{{ row[1] }}</td>
            <td>{{ row[2] }}</td>
            <td>{{ row[3] }}</td>
            <td>{{ row[4] }}</td>
            <td>{{ row[5] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def get_alerts():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Get the last 50 alerts, newest first
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

@app.route('/')
def index():
    alerts = get_alerts()
    return render_template_string(HTML_TEMPLATE, rows=alerts)

if __name__ == '__main__':
    # Run on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)