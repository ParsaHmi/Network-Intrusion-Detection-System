from flask import Flask, jsonify, render_template
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
DB = "traffic.db"

def get_db():
    return sqlite3.connect(DB)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/packets")
def packets():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT source_ip, destination_ip, protocol, packet_size, time
        FROM packets
        ORDER BY id DESC
        LIMIT 30
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/api/alerts")
def alerts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT source_ip, alert_description, date, time
        FROM alerts
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/api/traffic")
def traffic():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT protocol, SUM(packet_count)
        FROM traffic
        GROUP BY protocol
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)



@app.route("/api/traffic-timeline")
def traffic_timeline():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT protocol, start_time, packet_count
        FROM traffic
        ORDER BY date DESC, start_time DESC
        LIMIT 30
    """)
    rows = cur.fetchall()
    conn.close()

    rows.reverse()

    timeline = []
    data = {}

    for protocol, time, count in rows:
        if time not in timeline:
            timeline.append(time)
        data.setdefault(protocol, {})[time] = count

    series = {}
    for protocol in data:
        series[protocol] = [data[protocol].get(t, 0) for t in timeline]

    return jsonify({
        "labels": timeline,
        "series": series
    })




@app.route("/api/stats")
def stats():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT source_ip, COUNT(*) as cnt
        FROM packets
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 1
    """)
    top_talker = cur.fetchone()
    top_talker_ip = top_talker[0] if top_talker else None
    top_talker_count = top_talker[1] if top_talker else 0

    cur.execute("""
        SELECT destination_ip, COUNT(*) as cnt
        FROM packets
        GROUP BY destination_ip
        ORDER BY cnt DESC
        LIMIT 1
    """)
    top_listener = cur.fetchone()
    top_listener_ip = top_listener[0] if top_listener else None
    top_listener_count = top_listener[1] if top_listener else 0

    cur.execute("""
        SELECT port, COUNT(*) as cnt
        FROM (
            SELECT source_port AS port FROM packets
            UNION ALL
            SELECT destination_port AS port FROM packets
        )
        GROUP BY port
        ORDER BY cnt DESC
        LIMIT 1
    """)
    top_port = cur.fetchone()
    top_port_number = top_port[0] if top_port else None
    top_port_count = top_port[1] if top_port else 0

    now = datetime.now()

    cur.execute("""
        SELECT protocol, packet_count, start_time
        FROM traffic
        ORDER BY id DESC
        LIMIT 50
    """)

    total = defaultdict(int)

    for protocol, count, t in cur.fetchall():
        t_obj = datetime.strptime(t, "%H:%M:%S").replace(
            year=now.year, month=now.month, day=now.day
        )
        if (now - t_obj).total_seconds() <= 10:
            total[protocol] += count

    packet_rate = {proto: cnt / 10 for proto, cnt in total.items()}    
    conn.close()

    return jsonify({
        "top_talker": {"ip": top_talker_ip, "count": top_talker_count},
        "top_listener": {"ip": top_listener_ip, "count": top_listener_count},
        "top_port": {"port": top_port_number, "count": top_port_count},
        "packet_rate": packet_rate
    })

if __name__ == "__main__":
    app.run(debug=True, threaded=True)