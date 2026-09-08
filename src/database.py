import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '../alerts.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            detection_type TEXT,
            alert_name TEXT,
            severity TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert(src_ip, dst_ip, src_port, dst_port, protocol, detection_type, alert_name, severity):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (src_ip, dst_ip, src_port, dst_port, protocol, detection_type, alert_name, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, src_port, dst_port, protocol, detection_type, alert_name, severity))
    conn.commit()
    conn.close()

def fetch_recent_alerts(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    print("[+] Database initialized successfully.")