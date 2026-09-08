from flask import Flask, render_template, jsonify
from src.database import fetch_recent_alerts, init_db

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def api_alerts():
    alerts = fetch_recent_alerts(100)
    formatted = []
    for a in alerts:
        formatted.append({
            'id': a[0],
            'timestamp': a[1],
            'src_ip': a[2],
            'dst_ip': a[3],
            'src_port': a[4],
            'dst_port': a[5],
            'protocol': a[6],
            'detection_type': a[7],
            'alert_name': a[8],
            'severity': a[9]
        })
    return jsonify(formatted)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)