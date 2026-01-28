from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime , date
import threading
from queue import Queue
from collections import defaultdict
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
import time
import sqlite3

saving_queue = Queue()
analyz_queue = Queue()

conn1 = sqlite3.connect("traffic.db", check_same_thread=False)
cursor1 = conn1.cursor()
conn2 = sqlite3.connect("traffic.db", check_same_thread=False)
cursor2 = conn2.cursor()

port_treshold = 20
dhcp_request_count = 0
time_treshold = 20
abnormal_traffic_treshold = 100
broadcast_treshold = 20
ddos_treshold = 100
dhcp_treshold = 10
broadcast_count = 0

first_dhcp_time = None
first_packet_ddos = None
first_packet_scan = None
first_packet_counter = None
first_broadcast_time = None

ddos_counter = defaultdict(int)
port_scan_tracker = defaultdict(set)
traffic_counter = defaultdict(int)

def detect_port_scan(packet, now_time):
    global first_packet_scan, port_scan_tracker
    if first_packet_scan is None:
        first_packet_scan = now_time
    if time_diff(now_time, first_packet_scan) > time_treshold:
        first_packet_scan = now_time
        port_scan_tracker.clear()
    src = packet["source_ip"]
    dst_port = packet["destination_port"]
    if src and dst_port:
        port_scan_tracker[src].add(dst_port)
        if len(port_scan_tracker[src]) > port_treshold:
            return True
    return False


def detect_abnormal_traffic(packet, now_time):
    global first_packet_counter, traffic_counter
    if first_packet_counter is None:
        first_packet_counter = now_time
    if time_diff(now_time, first_packet_counter) > time_treshold:
        first_packet_counter = now_time
        traffic_counter.clear()
    src = packet["source_ip"]
    if src:
        traffic_counter[src] += 1
        if traffic_counter[src] > abnormal_traffic_treshold:
            return True
    return False


def detect_ddos(packet, now_time):
    global first_packet_ddos, ddos_counter
    if first_packet_ddos is None:
        first_packet_ddos = now_time
    if time_diff(now_time, first_packet_ddos) > time_treshold:
        first_packet_ddos = now_time
        ddos_counter.clear()
    dst = packet["destination_ip"]
    if dst:
        ddos_counter[dst] += 1
        if ddos_counter[dst] > ddos_treshold:
            return True
    return False


def detect_dhcp_server(packet):
    if packet["protocol"] == "UDP":
        if packet["source_port"] == 67 and packet["destination_port"] == 68:
            return True
    return False


def detect_broadcast_storm(packet, now_time):
    global broadcast_count, first_broadcast_time
    if first_broadcast_time is None:
        first_broadcast_time = now_time
        broadcast_count = 0

    if time_diff(first_broadcast_time, now_time) > time_treshold:
        first_broadcast_time = now_time
        broadcast_count = 0

    is_broadcast = (
        packet["destination_ip"] == "255.255.255.255"
        or packet["destination_ip"] is None
    )

    if packet["protocol"] in ["ARP", "IP"] and is_broadcast:
        broadcast_count += 1
        if broadcast_count > broadcast_treshold:
            return True
    return False




def detect_dhcp_starvation(packet, now_time):
    global dhcp_request_count, first_dhcp_time
    if packet["protocol"] != "UDP" or packet["destination_port"] != 67:
        return False

    if first_dhcp_time is None:
        first_dhcp_time = now_time
        dhcp_request_count = 0

    if time_diff(first_dhcp_time, now_time) > time_treshold:
        first_dhcp_time = now_time
        dhcp_request_count = 0
        
    dhcp_request_count += 1
    if dhcp_request_count > dhcp_treshold:
        return True
    return False




def time_diff(t1: str, t2: str) :
    def parse_time(t):
        try:
            return datetime.strptime(t, "%H:%M:%S.%f")
        except ValueError:
            return datetime.strptime(t, "%H:%M:%S")

    return abs((parse_time(t2) - parse_time(t1)).total_seconds())



def save_packet(packet):
    cursor1.execute("""
    INSERT INTO packets VALUES (NULL,?,?,?,?,?,?,?,?)
    """, (
        packet["source_ip"],
        packet["destination_ip"],
        packet["source_port"],
        packet["destination_port"],
        packet["protocol"],
        packet["size"],
        packet["date"],
        packet["time"]
    ))
    conn1.commit()


def save_traffic(protocol):
    today = datetime.now().strftime("%Y-%m-%d")
    now_time = datetime.now().strftime("%H:%M:%S")

    cursor1.execute("""
        SELECT id, packet_count, start_time
        FROM traffic
        WHERE protocol = ? AND date = ?
        ORDER BY id DESC
        LIMIT 1
    """, (protocol, today))

    row = cursor1.fetchone()

    if row:
        record_id, packet_count, start_time = row

        if time_diff(start_time, now_time) <= 10:
            cursor1.execute("""
                UPDATE traffic
                SET packet_count = packet_count + 1
                WHERE id = ?
            """, (record_id,))
        else:
            cursor1.execute("""
                INSERT INTO traffic (protocol, packet_count, date, start_time)
                VALUES (?, 1, ?, ?)
            """, (protocol, today, now_time))
    else:
        cursor1.execute("""
            INSERT INTO traffic (protocol, packet_count, date, start_time)
            VALUES (?, 1, ?, ?)
        """, (protocol, today, now_time))

    conn1.commit()



def save_alert(source_ip, alert_description, date, time):
    cursor2.execute("SELECT 1 FROM alerts WHERE source_ip = ? AND alert_description= ?", (source_ip,alert_description))
    if cursor2.fetchone() is None:
        cursor2.execute("""
            INSERT INTO alerts (source_ip, alert_description, date, time)
            VALUES (?, ?, ?, ?)
        """, (source_ip, alert_description, date, time))
        conn2.commit()



def process_packet(packet):

    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = None

    if packet.haslayer(ARP):
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    elif packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        else:
            protocol = "IP-OTHER"

    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        protocol = "IPv6"


    data = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "size": len(packet),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S")
    }
    print(packet)
    saving_queue.put(data)




def sniff_thread():
    print("start sniffing !")
    sniff(prn=process_packet, store=False)


def analysis_thread():
    print("start analyzing !\n")

    while True:
        data = analyz_queue.get()
        now_time =  datetime.now().strftime("%H:%M:%S")
        if detect_port_scan(data , now_time):
            date =  datetime.now().strftime("%Y-%m-%d")
            save_alert(data["source_ip"], "Port Scan", date , now_time)

        if detect_abnormal_traffic(data,now_time):
            date =  datetime.now().strftime("%Y-%m-%d")
            save_alert(data["source_ip"], "Abnormal Traffic", date , now_time)

        if detect_ddos(data, now_time):
            date = datetime.now().strftime("%Y-%m-%d")
            save_alert(data["destination_ip"], "Possible DDoS Attack", date, now_time)

        if detect_dhcp_server(data):
            date = datetime.now().strftime("%Y-%m-%d")
            save_alert(data["source_ip"], "DHCP Server Detected", date, now_time)

        if detect_broadcast_storm(data,now_time):
            date = datetime.now().strftime("%Y-%m-%d")
            save_alert(data["source_ip"], "BroadCast Storm Detected", date, now_time)

        if detect_dhcp_starvation(data,now_time):
            date = datetime.now().strftime("%Y-%m-%d")
            save_alert(data["source_ip"], "DHCP Starvation Detected", date, now_time)

        analyz_queue.task_done()



def save_to_database() :

    while True:
        data = saving_queue.get()
        analyz_queue.put(data)

        try:
            save_packet(data)
            save_traffic(data["protocol"])

        finally:
            saving_queue.task_done()




t1 = threading.Thread(target=sniff_thread, daemon=True)
t2 = threading.Thread(target=analysis_thread, daemon=True)
t3 = threading.Thread(target=save_to_database, daemon=True)

print("started !\npress Ctrl + C to stop")

t1.start()
t2.start()
t3.start()


try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping...")