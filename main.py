import os
import sqlite3
import threading
from datetime import datetime, timedelta, time
import time
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from flask import Flask, render_template
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff

matplotlib.use('Agg')

app = Flask(__name__)

# Veritabanlarını ve tabloları oluşturma fonksiyonu
def initialize_databases():
    with sqlite3.connect('packet_data_main.db') as conn_main:
        cursor_main = conn_main.cursor()
        cursor_main.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                destination_mac TEXT,
                source_mac TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                packet_size INTEGER
            )
        ''')
        conn_main.commit()

    with sqlite3.connect('alarm_data.db') as conn_alarm:
        cursor_alarm = conn_alarm.cursor()
        cursor_alarm.execute('''
            CREATE TABLE IF NOT EXISTS alarms (
                id INTEGER PRIMARY KEY,
                message TEXT,
                alarm_type TEXT,
                score INTEGER,
                anomaly_time TEXT
            )
        ''')
        conn_alarm.commit()

        cursor_alarm.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY,
                message TEXT,
                alarm_type TEXT,
                score INTEGER,
                anomaly_time TEXT
            )
        ''')
        conn_alarm.commit()

initialize_databases()

# Paket yakalama işlemi
def start_packet_capture():
    sniff(prn=handle_ethernet_frame, store=0)

# Paket yakalama thread'i
def packet_sniffer():
    start_packet_capture()

# Paket verilerini veritabanına ekleme fonksiyonu
def add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size=None):
    with sqlite3.connect('packet_data_main.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, packet_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size))
        conn.commit()

# Ethernet frame'lerini işleme fonksiyonu
def handle_ethernet_frame(frame):
    dst_mac = frame.dst
    src_mac = frame.src
    eth_type = frame.type
    timestamp = datetime.now()
    packet_size = len(frame.payload) if frame.payload else 0

    if eth_type == 0x0800 and frame.haslayer(IP):
        handle_ip_packet(frame[IP], timestamp, dst_mac, src_mac, packet_size)
    else:
        handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac, packet_size)
    add_packet_to_db(timestamp, dst_mac, src_mac, None, None, None, None, "Ethernet", packet_size)

# IP paketlerini işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, packet_size):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac, packet_size)

# Transport layer paketlerini işleme fonksiyonu
def handle_transport_layer(packet, src_ip, dst_ip, timestamp, dst_mac, src_mac, packet_size):
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # HTTP kontrolü (port 80)
        if src_port == 80 or dst_port == 80:
            handle_packet(src_ip, dst_ip, src_port, dst_port, "HTTP", timestamp, dst_mac, src_mac, packet_size)
        # FTP kontrolü (port 21)
        elif src_port == 21 or dst_port == 21:
            handle_packet(src_ip, dst_ip, src_port, dst_port, "FTP", timestamp, dst_mac, src_mac, packet_size)
        else:
            handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac, packet_size)

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac, packet_size)

    elif packet.haslayer(ICMP):
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac, packet_size)

    else:
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac, packet_size)
# Paketleri işleme ve veritabanına kaydetme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac, packet_size):
    add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size)

def get_last_20_packets():
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT timestamp, source_ip, destination_ip, protocol, packet_size FROM packets ORDER BY timestamp DESC LIMIT 20')
        packets = cursor.fetchall()
        return packets
    finally:
        cursor.close()
        conn.close()


# Grafik oluşturma fonksiyonları
def generate_packet_count_graph(threshold_value=20):
    packet_count_graph_filename = 'packet_count_graph.png'
    graph_path = os.path.join('static', packet_count_graph_filename)

    with sqlite3.connect('packet_data_main.db') as conn:
        cursor = conn.cursor()
        ten_seconds_ago = datetime.now() - timedelta(seconds=30)
        cursor.execute('SELECT timestamp FROM packets WHERE timestamp >= ?', (ten_seconds_ago,))
        rows = cursor.fetchall()

    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]
    num_seconds = 30
    packet_counts = [0] * (num_seconds + 1)

    for timestamp in timestamps:
        second_index = int(timestamp - ten_seconds_ago.timestamp())
        packet_counts[second_index] += 1

    over_threshold_indices = [i for i, count in enumerate(packet_counts) if count >= threshold_value]

    plt.plot(range(num_seconds + 1), packet_counts, color='blue')
    plt.axhline(y=threshold_value, color='red', linestyle='--', label='Threshold')
    for index in over_threshold_indices:
        plt.fill_between([index, index + 1], [packet_counts[index], packet_counts[index]], threshold_value, color='red', alpha=0.3)
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packets per second')
    plt.title('Packet Count Over Time')
    plt.grid(True)
    plt.legend()


    plt.savefig(graph_path)
    plt.close()
    return packet_count_graph_filename
def generate_protocol_distribution_graph():
    protocol_distribution_graph_filename = 'protocol_distribution_graph.png'
    graph_path = os.path.join('static', protocol_distribution_graph_filename)

    with sqlite3.connect('packet_data_main.db') as conn:
        cursor = conn.cursor()
        thirty_seconds_ago = datetime.now() - timedelta(seconds=30)
        cursor.execute('SELECT protocol, COUNT(*) FROM packets WHERE timestamp >= ? GROUP BY protocol', (thirty_seconds_ago,))
        rows = cursor.fetchall()

    protocols = [row[0] for row in rows]
    counts = [row[1] for row in rows]

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140)
    plt.title('Packet Count by Protocol in Last 30 Seconds')
    plt.savefig(graph_path)
    plt.close()
    return protocol_distribution_graph_filename
def generate_ethernet_frame_count_graph():
    ethernet_frame_count_graph_filename = 'ethernet_frame_count_graph.png'
    graph_path = os.path.join('static', ethernet_frame_count_graph_filename)

    with sqlite3.connect('packet_data_main.db') as conn:
        cursor = conn.cursor()
        ten_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('SELECT timestamp FROM packets WHERE timestamp >= ? AND protocol = "Ethernet"', (ten_seconds_ago,))
        rows = cursor.fetchall()

    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]
    num_seconds = 10
    ethernet_frame_counts = [0] * (num_seconds + 1)

    for timestamp in timestamps:
        second_index = int(timestamp - ten_seconds_ago.timestamp())
        ethernet_frame_counts[second_index] += 1

    plt.plot(range(num_seconds + 1), ethernet_frame_counts, color='green')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Ethernet Frames per second')
    plt.title('Ethernet Frame Count Over Time')
    plt.grid(True)
    plt.savefig(graph_path)
    plt.close()
    return ethernet_frame_count_graph_filename

def generate_mac_address_packet_count_graph():
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        ten_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT destination_mac, COUNT(*) 
            FROM packets 
            WHERE timestamp >= ? 
            GROUP BY destination_mac 
            ORDER BY COUNT(*) DESC 
            LIMIT 10
        ''', (ten_seconds_ago,))
        rows = cursor.fetchall()

        mac_addresses = [row[0] for row in rows]
        packet_counts = [row[1] for row in rows]

        plt.figure(figsize=(10, 6))
        plt.bar(mac_addresses, packet_counts, color='purple')
        plt.xlabel('MAC Addresses')
        plt.ylabel('Packet Count')
        plt.title('Top 10 MAC Addresses by Packet Count in Last 10 Seconds')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.grid(True)

        mac_address_packet_count_graph = 'mac_address_packet_count_graph.png'
        graph_path = os.path.join('static', mac_address_packet_count_graph)

        plt.savefig(graph_path)
        plt.close()
        return mac_address_packet_count_graph
    finally:
        cursor.close()
        conn.close()
# beşinci grafik oluşturma fonksiyonu
def generate_port_usage_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 20 saniye içinde gelen paket sayısını al
        twenty_seconds_ago = datetime.now() - timedelta(seconds=20)
        cursor.execute('''
            SELECT destination_port, COUNT(*) 
            FROM packets 
            WHERE timestamp >= ? 
            GROUP BY destination_port 
            ORDER BY COUNT(*) DESC 
            LIMIT 10
        ''', (twenty_seconds_ago,))
        rows = cursor.fetchall()

        # Verileri işle ve portları ve paket sayılarını al
        ports = [str(row[0]) for row in rows]
        packet_counts = [row[1] for row in rows]

        # Eğer ports listesi 10'dan az elemana sahipse, eksik olan elemanları 0 olarak doldur
        if len(ports) < 10:
            missing_ports_count = 10 - len(ports)
            ports.extend([''] * missing_ports_count)
            packet_counts.extend([0] * missing_ports_count)

        # Grafik oluştur
        plt.figure(figsize=(10, 6))
        plt.bar(ports, packet_counts, color='skyblue', align='center')
        plt.xlabel('Destination Port')
        plt.ylabel('Packet Count')
        plt.title('Packet Count by Destination Port (Top 10) - Last 20 Seconds')
        plt.xticks(rotation=45)
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        port_usage_graph = 'port_usage_graph_last_20_seconds.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', port_usage_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return port_usage_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()

# altıncı grafik oluşturma fonksiyonu
def generate_packet_size_distribution_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Paket boyutlarını al
        cursor.execute('''
            SELECT packet_size 
            FROM packets 
            WHERE timestamp >= ?
        ''', (datetime.now() - timedelta(seconds=20),))
        rows = cursor.fetchall()

        # Verileri işle ve paket boyutlarını al
        packet_sizes = [row[0] for row in rows]

        # Grafik oluştur
        plt.figure(figsize=(10, 6))
        plt.hist(packet_sizes, bins=50, color='skyblue')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.title('Packet Size Distribution - Last 20 Seconds')
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        packet_size_distribution_graph = 'packet_size_distribution_graph_last_20_seconds.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', packet_size_distribution_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return packet_size_distribution_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()


conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
cursor_alarm = conn_alarm.cursor()
# Alarm detection and handling
def detect_anomalies():
    while True:
        data = pd.read_sql_query('SELECT * FROM packets', conn_main)
        anomalies, alarm_messages = detect_access_anomalies(data)
        anomalies, syn_alarm_messages = detect_syn_flood(data)
        anomalies, traffic_alarm_messages = detect_high_traffic(data)
        anomalies, protocol_alarm_messages = detect_protocol_violations(data)

        all_alarm_messages = alarm_messages + syn_alarm_messages + traffic_alarm_messages + protocol_alarm_messages
        for alarm in all_alarm_messages:
            add_alarm_to_db(alarm['message'], alarm['alarm_type'], alarm['score'], alarm['anomaly_time'])

        time.sleep(10)
# Alarm ekleme fonksiyonu
def add_alarm_to_db(message, alarm_type, score, anomaly_time):
    with sqlite3.connect('alarm_data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alarms (message, alarm_type, score, anomaly_time)
            VALUES (?, ?, ?, ?)
        ''', (message, alarm_type, score, anomaly_time))
        conn.commit()

def detect_access_anomalies(data):
    anomalies = pd.DataFrame(columns=data.columns)
    alarm_messages = []

    normal_hours_start = 9
    normal_hours_end = 18
    threshold = data['packet_size'].mean()  # Dinamik eşik değeri
    mean_packet_size = 250
    for index, row in data.iterrows():
        timestamp = pd.to_datetime(row['timestamp'])
        hour = timestamp.hour
        packet_size = row['packet_size']

        if packet_size > threshold:
            risk_score = calculate_risk_score(packet_size, threshold)
            if hour < normal_hours_start or hour > normal_hours_end:
                # Risk skorunu hesapla (dinamik olarak)

                alarm = {
                    'message': f"{row['source_ip']} IP adresi, normal çalışma saatleri dışında ({timestamp.strftime('%Y-%m-%d %H:%M:%S')}) ({packet_size} bayt) boyutunda paket tespit edildi.",
                    'alarm_type': 'Anomaly IP',
                    'score': risk_score,
                    'anomaly_time': timestamp.strftime('%Y-%m-%d %H:%M:%S')
                }
                if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                    alarm_messages.append(alarm)
                    anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)
            else:
                initiator_ip = row['source_ip']
                application_id = row['protocol']
                transferred_bytes = packet_size
                timestamp = pd.to_datetime(row['timestamp']).strftime('%d %b %Y, %H:%M')
                anomaly_message = f"Başlatıcı IP {initiator_ip}, {application_id} kullanırken " \
                                  f"yaklaşık olarak {timestamp} civarında {transferred_bytes} bayt veri aktardı. " \
                                  f"Bu belirli yakalama arayüzü, zaman, IP başlatıcı ve uygulama kimliği kombinasyonu için " \
                                  f" ortalama paket boyutu {mean_packet_size} bayttır. " \
                                  f"Bu ortalama değerden sapma derecesi {risk_score:.2f} puan aldı."

                alarm = {
                    'message': anomaly_message,
                    'alarm_type': 'Overflow Alarm',
                    'score': risk_score,
                    'anomaly_time': timestamp
                }

                if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                    alarm_messages.append(alarm)
                    anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)


        return anomalies,alarm_messages


def detect_syn_flood(data):
    anomalies = pd.DataFrame(columns=data.columns)
    alarm_messages = []

    # SYN paketlerini tespit et
    syn_packets = data[data['protocol'] == 'TCP']  # TCP protokolü kontrolü
    if 'packet_flags' in data.columns:
        syn_packets = syn_packets[syn_packets['packet_flags'].str.contains('S', na=False)]

    # Aynı IP'den gelen SYN paketlerini ve zaman damgalarını grupla
    syn_packets['timestamp'] = pd.to_datetime(syn_packets['timestamp'])
    grouped_syn_packets = syn_packets.groupby('source_ip')

    for ip, group in grouped_syn_packets:
        group = group.sort_values(by='timestamp')
        count = 0
        for i in range(len(group) - 1):
            if (group.iloc[i + 1]['timestamp'] - group.iloc[i]['timestamp']).total_seconds() <= 5:
                count += 1
                if count >= 200:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    alarm_message = {
                        'message': f"{ip} IP adresi, 5 saniye içinde {count + 1} adet SYN paketi gönderdi, bu bir SYN flooding saldırısına işaret ediyor olabilir.",
                        'alarm_type': 'SYN Flood',
                        'score': 9,
                        'anomaly_time': timestamp
                    }
                    alarm_messages.append(alarm_message)
                    anomalies = pd.concat([anomalies, group], ignore_index=True)
                    break
            else:
                count = 0

    return anomalies, alarm_messages

def detect_high_traffic(data):
    anomalies = pd.DataFrame(columns=data.columns)
    alarm_messages = []

    high_traffic_threshold = 1000  # Eşik değer
    threshold_risk_score = 7  # Eşik değere göre belirlenecek risk skoru

    if 'destination_port' in data.columns:
        traffic_counts = data['destination_port'].value_counts()

        for port, count in traffic_counts.items():
            if count > high_traffic_threshold:
                # Dinamik risk skoru hesapla
                risk_score = min(10, int(threshold_risk_score * (count / high_traffic_threshold)))

                alarm = {
                    'message': f"Port {port}'de yüksek seviyede trafik tespit edildi, {count} paket ile.",
                    'alarm_type': 'High Traffic Port',
                    'score': risk_score,  # Dinamik risk skoru
                    'anomaly_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                    alarm_messages.append(alarm)
                    anomalies = pd.concat([anomalies, data[data['destination_port'] == port].dropna()], ignore_index=True)

    else:
        print("The 'destination_port' column is missing from the data.")

    return anomalies, alarm_messages

def detect_protocol_violations(data):
    anomalies = pd.DataFrame(columns=data.columns)
    alarm_messages = []

    for index, row in data.iterrows():
        protocol = row['protocol']

        if protocol == 'HTTP' :
            alarm = {
                'message': f"Güvensiz protokol {protocol}, {row['timestamp']} tarihinde {row['destination_port']} numaralı portta tespit edildi.",
                'alarm_type': 'Unsecure Protocol',
                'score': 7,
                'anomaly_time': row['timestamp']
            }
            alarm_messages.append(alarm)
            anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)

    return anomalies, alarm_messages

def calculate_risk_score(packet_size, threshold):
    base_score = 5
    if packet_size > threshold:
        return min(10, base_score + (packet_size - threshold) / threshold)
    return base_score

def generate_minute_wise_alarm_graph():
   # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('alarm_data.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 1 saat içindeki alarm verilerini al
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=1)
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:%M:00', anomaly_time) as minute, COUNT(*) 
            FROM alarms 
            WHERE anomaly_time >= ? AND anomaly_time <= ? 
            GROUP BY minute
            ORDER BY minute
        ''', (start_time, end_time))
        rows = cursor.fetchall()

        # Veriyi işleyip dakikaya göre alarm sayısını hesapla
        minutes = [start_time + timedelta(minutes=i) for i in range(60)]
        minute_labels = [minute.strftime('%H:%M') for minute in minutes]
        alarm_counts = {row[0]: row[1] for row in rows}
        counts = [alarm_counts.get(minute.strftime('%Y-%m-%d %H:%M:00'), 0) for minute in minutes]

        # Grafik oluştur
        plt.figure(figsize=(12, 6))
        plt.plot(minute_labels, counts, marker='o', color='b')
        plt.xlabel('Time (HH:MM)')
        plt.ylabel('Number of Alarms')
        plt.title('Alarms per Minute - Last Hour')
        plt.xticks(rotation=90)
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        minute_wise_alarm_graph = 'minute_wise_alarm_graph_last_hour.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', minute_wise_alarm_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return minute_wise_alarm_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()

# Last Minute Alarms fonksiyonu
def get_last_minute_alarm_count():
    # Şu anki zamanı al
    current_time = datetime.now()

    # Bir önceki dakikanın zaman aralığını belirle
    start_time = current_time - timedelta(minutes=10)

    # Veritabanından son dakikadaki alarm sayısını al
    with sqlite3.connect('alarm_data.db', check_same_thread=False) as conn_alarm:
        cursor_alarm = conn_alarm.cursor()
        cursor_alarm.execute('SELECT COUNT(*) FROM alarms WHERE anomaly_time >= ?', (start_time,))
        alarmCount = cursor_alarm.fetchone()[0]

    return alarmCount
# Alarm Type Distribution fonksiyonu
def generate_alarm_type_distribution_chart():
    # Alarm türlerini ve sayılarını veritabanından al
    with sqlite3.connect('alarm_data.db', check_same_thread=False) as conn_alarm:
        cursor_alarm = conn_alarm.cursor()
        cursor_alarm.execute('SELECT alarm_type, COUNT(*) FROM alarms GROUP BY alarm_type')
        rows = cursor_alarm.fetchall()

    # Verileri grafik oluşturmak için hazırla
    labels = [row[0] for row in rows]
    counts = [row[1] for row in rows]

    # Pasta grafiğini oluştur
    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Alarm Type Distribution')
    plt.axis('equal')  # Daireyi daire olarak tutar

    # Grafik dosyasının adını sabit tut
    chart_filename = 'alarm_type_distribution_chart.png'

    # Grafik dosyasının yolunu belirle
    chart_path = os.path.join('static', chart_filename)

    # Grafik dosyasını kaydet
    plt.savefig(chart_path)
    plt.close()

    return chart_filename  # Grafik dosya adını döndür


@app.route('/anomalies')
def anomalies():
    # Veritabanından son anomalileri al
    cursor_alarm.execute('SELECT * FROM alarms ORDER BY anomaly_time DESC LIMIT 20')
    alarm_messages = cursor_alarm.fetchall()
    alarm_messages = [
            {
                'id': row[0],
                'message': row[1],
                'alarm_type': row[2],
                'score': row[3],
                'anomaly_time': row[4]
            }
            for row in alarm_messages
        ]

    # Grafik dosyasının adını döndüren fonksiyonu çağır
    minute_wise_alarm_graph_file = generate_minute_wise_alarm_graph()
    alarm_type_distribution_chart_file = generate_alarm_type_distribution_chart()
    last_minute_alarm_count = get_last_minute_alarm_count()

    return render_template('anomalies.html', alarm_messages=alarm_messages, minute_wise_alarm_graph_file=minute_wise_alarm_graph_file, alarm_type_distribution_chart_file=alarm_type_distribution_chart_file, last_minute_alarm_count=last_minute_alarm_count)

# Flask route'ları
@app.route('/')
def index():
    packet_count_graph = generate_packet_count_graph()
    protocol_distribution_graph = generate_protocol_distribution_graph()
    ethernet_frame_count_graph = generate_ethernet_frame_count_graph()
    mac_address_packet_count_graph = generate_mac_address_packet_count_graph()
    # Beşinci grafik dosyasını oluştur ve adını al
    port_usage_graph_filename=generate_port_usage_graph()
    # Yedinci grafik dosyasını oluştur ve adını al
    packet_size_distribution_graph_filename=generate_packet_size_distribution_graph()
    last_20_packets = get_last_20_packets()

    return render_template('index.html',
                           packet_count_graph_filename=packet_count_graph,
                           protocol_distribution_graph_filename=protocol_distribution_graph,
                           ethernet_frame_count_graph_filename=ethernet_frame_count_graph,
                           mac_address_packet_count_graph_filename=mac_address_packet_count_graph,
                           port_usage_graph_filename=port_usage_graph_filename,
                           packet_size_distribution_graph_filename=packet_size_distribution_graph_filename,
                           last_20_packets=last_20_packets)



if __name__ == '__main__':
    # Paket yakalama ve alarm kontrol thread'lerini başlatma
    conn_main = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    packet_sniffer_thread = threading.Thread(target=packet_sniffer)
    packet_sniffer_thread.start()
    anomaly_detection_thread = threading.Thread(target=detect_anomalies, daemon=True)
    anomaly_detection_thread.start()
    # Flask uygulamasını başlatma
    app.run(host='0.0.0.0', port=5000, debug=True)
