import socket
import sqlite3
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from flask import Flask, render_template, url_for
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import matplotlib.pyplot as plt
import os
from collections import defaultdict
import time
import matplotlib
import uuid


matplotlib.use('Agg')

app = Flask(__name__)

# Function to create database tables if they don't exist
def initialize_databases():
    conn_main = sqlite3.connect('packet_data_main.db', check_same_thread=False)
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
    cursor_main.close()
    conn_main.close()

    conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
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
    cursor_alarm.close()
    conn_alarm.close()

    # Create anomalies table if not exists
    conn_anomalies = sqlite3.connect('alarm_data.db', check_same_thread=False)
    cursor_anomalies = conn_anomalies.cursor()
    cursor_anomalies.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY,
            message TEXT,
            alarm_type TEXT,
            score INTEGER,
            anomaly_time TEXT
        )
    ''')
    conn_anomalies.commit()
    cursor_anomalies.close()
    conn_anomalies.close()

initialize_databases()

# Function to start packet capture
def start_packet_capture():
    sniff(prn=handle_ethernet_frame, store=0)

# Thread function to sniff packets
def packet_sniffer():
    start_packet_capture()

# Function to add packet data to the database
def add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size=None):
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, packet_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size))
    conn.commit()
    cursor.close()
    conn.close()

# Function to handle Ethernet frames
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

# Function to handle IP packets
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, packet_size):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac, packet_size)

# Function to handle transport layer packets
def handle_transport_layer(packet, src_ip, dst_ip, timestamp, dst_mac, src_mac, packet_size):
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac, packet_size)
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac, packet_size)
    elif packet.haslayer(ICMP):
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac, packet_size)
    else:
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac, packet_size)

# Function to handle packets and save to database
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac, packet_size):
    add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size)

def generate_packet_count_graph(threshold_value=20):
    packet_count_graph_filename = 'packet_count_graph.png'
    graph_path = os.path.join('static', packet_count_graph_filename)

    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
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
    finally:
        cursor.close()
        conn.close()
# İkinci grafik oluşturma fonksiyonu
def generate_protocol_distribution_graph():
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        thirty_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('SELECT protocol, COUNT(*) FROM packets WHERE timestamp >= ? GROUP BY protocol', (thirty_seconds_ago,))
        rows = cursor.fetchall()

        protocols = [row[0] for row in rows]
        counts = [row[1] for row in rows]

        plt.figure(figsize=(8, 6))
        plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140)
        plt.title('Packet Count by Protocol in Last 30 Seconds')

        protocol_distribution_graph = 'protocol_distribution_graph.png'
        graph_path = os.path.join('static', protocol_distribution_graph)

        plt.savefig(graph_path)
        plt.close()
        return protocol_distribution_graph
    finally:
        cursor.close()
        conn.close()

def generate_ethernet_frame_count_graph():
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
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

        ethernet_frame_count_graph = 'ethernet_frame_count_graph.png'
        graph_path = os.path.join('static', ethernet_frame_count_graph)

        plt.savefig(graph_path)
        plt.close()
        return ethernet_frame_count_graph
    finally:
        cursor.close()
        conn.close()

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

def generate_mac_address_packet_count_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 20 saniye içinde gelen paket sayısını al
        twenty_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT destination_mac, COUNT(*) 
            FROM packets 
            WHERE timestamp >= ? 
            GROUP BY destination_mac 
            ORDER BY COUNT(*) DESC 
            LIMIT 10
        ''', (twenty_seconds_ago,))
        rows = cursor.fetchall()

        # Verileri işle ve MAC adreslerini ve paket sayılarını al
        mac_addresses = [row[0] for row in rows]
        packet_counts = [row[1] for row in rows]

        # Grafik oluştur
        plt.figure(figsize=(10, 6))
        plt.bar(mac_addresses, packet_counts, color='skyblue')
        plt.xlabel('Destination MAC Address')
        plt.ylabel('Packet Count')
        plt.title('Packet Count by Destination MAC Address (Top 10) - Last 20 Seconds')
        plt.xticks(rotation=45)  # MAC adreslerini 45 derece döndür
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        mac_address_packet_count_graph = 'mac_address_packet_count_graph_last_20_seconds.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', mac_address_packet_count_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return mac_address_packet_count_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
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

# Last Minute Alarms fonksiyonu
def get_last_minute_alarm_count():
    # Şu anki zamanı al
    current_time = datetime.now()

    # Bir önceki dakikanın zaman aralığını belirle
    start_time = current_time - timedelta(minutes=1)

    # Veritabanından son dakikadaki alarm sayısını al
    with sqlite3.connect('alarm_data.db', check_same_thread=False) as conn_alarm:
        cursor_alarm = conn_alarm.cursor()
        cursor_alarm.execute('SELECT COUNT(*) FROM alarms WHERE anomaly_time >= ?', (start_time,))
        alarmCount = cursor_alarm.fetchone()[0]

    return alarmCount
# Veritabanı bağlantısı oluştur
conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
cursor_alarm = conn_alarm.cursor()

# Yeni tabloyu oluştur
cursor_alarm.execute('''
    CREATE TABLE IF NOT EXISTS alarms (
        id INTEGER PRIMARY KEY,
        message TEXT,
        alarm_type TEXT,
        score INTEGER,
        anomaly_time TEXT
        
    )
''')

# Değişiklikleri kaydet
conn_alarm.commit()
# Ana veritabanında paket verilerini çekmek için fonksiyon
def fetch_packet_data():
    try:
        with sqlite3.connect('packet_data_main.db', check_same_thread=False) as conn_main:
            cursor_main = conn_main.cursor()
            cursor_main.execute('SELECT * FROM packets')
            rows = cursor_main.fetchall()
            if len(rows) > 0:
                columns = ['id','timestamp', 'destination_mac', 'source_mac', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'packet_size']
                packet_data = pd.DataFrame(rows, columns=columns)
                return packet_data
            else:
                return pd.DataFrame()
    except Exception as e:
        print("Error fetching packet data:", e)
        return None

def perform_statistical_analysis(packet_data):
    try:
        if packet_data is not None and not packet_data.empty:
            # Remove rows with all NA values
            packet_data.dropna(how='all', inplace=True)
            # Perform statistical analysis
            anomalies, alarm_messages = anomaly_detection_model.statistical_analysis(packet_data)
            return anomalies, alarm_messages
        else:
            print("Packet data is empty or None. Statistical analysis cannot be performed.")
            return None, []
    except Exception as e:
        print("Error performing statistical analysis:", e)
        return None, []


# Alarm mesajlarını ve istatistikleri veritabanına kaydetmek için fonksiyon
def save_data_to_database(anomalies, alarm_messages):
    try:
        # Alarm mesajlarını ve istatistikleri veritabanına kaydet
        conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
        cursor_alarm = conn_alarm.cursor()
        for message in alarm_messages:
            cursor_alarm.execute('''
                INSERT INTO alarms (message)
                VALUES (?)
            ''', (message,))
        conn_alarm.commit()
    except Exception as e:
        print("Error saving data to database:", e)

# Modeli güncelle
class AnomalyDetectionModel:
    def __init__(self):
        self.baseline = None
        self.establish_baseline()

    def establish_baseline(self):
        self.baseline = {
            'mean_packet_size': 1500,
            'std_packet_size': 100
        }

    def calculate_risk_score(self, packet_size):
        threshold = 1500
        if packet_size > threshold:
            scaled_score = 1 + (packet_size - threshold) / 100
            return min(10, int(scaled_score))
        else:
            return 1

    def statistical_analysis(self, data):
        anomalies = pd.DataFrame(columns=data.columns)
        alarm_messages = []

        for index, row in data.iterrows():
            packet_size = row['packet_size']
            mean_packet_size = self.baseline['mean_packet_size']
            std_packet_size = self.baseline['std_packet_size']
            z_score = (packet_size - mean_packet_size) / std_packet_size
            risk_score = self.calculate_risk_score(packet_size)

            if packet_size > mean_packet_size:
                initiator_ip = row['source_ip']
                application_id = row['protocol']
                transferred_bytes = packet_size
                timestamp = pd.to_datetime(row['timestamp']).strftime('%d %b %Y, %H:%M')
                anomaly_message = f"Initiator IP {initiator_ip}, while using {application_id}, " \
                                  f"transferred {transferred_bytes} bytes at around {timestamp}. " \
                                  f"The mean for this same capture interface + time + IP initiator + " \
                                  f"application ID combination is {mean_packet_size} bytes. " \
                                  f"That degree of deviation from the mean gets a score of {risk_score:.2f}."

                alarm = {
                    'message': anomaly_message,
                    'alarm_type': 'Overflow Alarm',
                    'score': risk_score,
                    'anomaly_time': timestamp
                }

                if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                    alarm_messages.append(alarm)
                    anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)

        access_anomalies, access_alarms = self.detect_access_anomalies(data)
        traffic_anomalies, traffic_alarms = self.detect_high_traffic(data)
        protocol_anomalies, protocol_alarms = self.detect_protocol_violations(data)
        syn_flood_anomalies, syn_flood_alarms = self.detect_syn_flood(data)

        anomalies = pd.concat([anomalies, access_anomalies, traffic_anomalies, protocol_anomalies], ignore_index=True)
        alarm_messages.extend(access_alarms)
        alarm_messages.extend(traffic_alarms)
        alarm_messages.extend(protocol_alarms)
        alarm_messages.extend(syn_flood_alarms)
        return anomalies, alarm_messages

    def detect_access_anomalies(self, data):
        anomalies = pd.DataFrame(columns=data.columns)
        alarm_messages = []

        normal_hours_start = 9
        normal_hours_end = 17
        threshold = self.baseline['mean_packet_size']  # Eşik değer

        for index, row in data.iterrows():
            timestamp = pd.to_datetime(row['timestamp'])
            hour = timestamp.hour
            packet_size = row['packet_size']

            if hour < normal_hours_start or hour > normal_hours_end or packet_size > threshold:
                # Risk skorunu hesapla (dinamik olarak)
                risk_score = self.calculate_risk_score(packet_size)

                alarm = {
                    'message': f"IP {row['source_ip']} accessed outside normal working hours or with abnormal packet size ({packet_size} bytes) at {timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    'alarm_type': 'Anomaly IP',
                    'score': risk_score,
                    'anomaly_time': timestamp.strftime('%Y-%m-%d %H:%M:%S')
                }
                if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                    alarm_messages.append(alarm)
                    anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)

        return anomalies, alarm_messages
    def detect_syn_flood(self, data):
        anomalies = pd.DataFrame(columns=data.columns)
        alarm_messages = []

        # SYN paketlerini tespit et
        syn_packets = data[data['protocol'] == 'TCP']  # TCP protokolü kontrolü
        if 'packet_flags' in data.columns:
            syn_packets = syn_packets[syn_packets['packet_flags'].str.contains('SYN', na=False)]

        # Aynı IP'den gelen SYN paketlerini ve zaman damgalarını grupla
        syn_packets['timestamp'] = pd.to_datetime(syn_packets['timestamp'])
        grouped_syn_packets = syn_packets.groupby('source_ip')

        for ip, group in grouped_syn_packets:
            group = group.sort_values(by='timestamp')
            count = 0
            for i in range(len(group) - 1):
                if (group.iloc[i + 1]['timestamp'] - group.iloc[i]['timestamp']).total_seconds() <= 5:
                    count += 1
                    if count >= 15:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        alarm_message = {
                            'message': f"IP {ip} has sent {count + 1} SYN packets within 5 seconds, indicating a possible SYN flood attack.",
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

    def detect_high_traffic(self, data):
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
                        'message': f"High traffic detected on port {port} with {count} packets",
                        'alarm_type': 'High Traffic Port',
                        'score': risk_score,  # Dinamik risk skoru
                        'anomaly_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    if risk_score >= 7:  # Skor 7'den büyükse alarm ekle
                        alarm_messages.append(alarm)
                        anomalies = pd.concat([anomalies, data[data['destination_port'] == port]], ignore_index=True)

        else:
            print("The 'destination_port' column is missing from the data.")

        return anomalies, alarm_messages

    def detect_protocol_violations(self, data):
        anomalies = pd.DataFrame(columns=data.columns)
        alarm_messages = []

        for index, row in data.iterrows():
            protocol = row['protocol']

            if protocol == 'HTTP':
                alarm = {
                    'message': f"Unsecure protocol {protocol} detected on port {row['destination_port']} at {row['timestamp']}",
                    'alarm_type': 'Unsecure Protocol',
                    'score': 7,
                    'anomaly_time': row['timestamp']
                }
                alarm_messages.append(alarm)
                anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)

        return anomalies, alarm_messages

# Modeli oluştur
anomaly_detection_model = AnomalyDetectionModel()

# Alarm mesajlarını kaydetme fonksiyonu
def save_alarms_to_db(alarm_messages):
    conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
    cursor_alarm = conn_alarm.cursor()
    for alarm in alarm_messages:
        anomaly_time = pd.to_datetime(alarm['anomaly_time']) if isinstance(alarm['anomaly_time'], str) else alarm['anomaly_time']
        cursor_alarm.execute('''
            INSERT INTO alarms (message, alarm_type, score, anomaly_time)
            VALUES (?, ?, ?, ?)
        ''', (alarm['message'], alarm['alarm_type'], alarm['score'], anomaly_time.strftime('%Y-%m-%d %H:%M:%S')))
    conn_alarm.commit()
    cursor_alarm.close()
    conn_alarm.close()
packet_data = fetch_packet_data()

if packet_data is not None:
    # Anomalileri tespit et ve alarm mesajlarını al
    anomalies, alarm_messages = anomaly_detection_model.statistical_analysis(packet_data)

    # Alarm mesajlarını veritabanına kaydet
    save_alarms_to_db(alarm_messages)

    # Alarm mesajlarını ekrana yazdır
    for message in alarm_messages:
        print(message)
else:
    print("Packet data is None. Statistical analysis cannot be performed.")
# Veritabanından paket verilerini almak ve istatistiksel analiz yapmak için bir thread
def process_packet_data():
    while True:
        # Veritabanından paket verilerini al
        packet_data = fetch_packet_data()

        if packet_data is not None:
            # İstatistiksel analiz yap
            anomalies, alarm_messages = perform_statistical_analysis(packet_data)

            # Alarm mesajlarını ve istatistikleri veritabanına kaydet
            save_alarms_to_db(alarm_messages)

        # Belirli bir süre bekle (örneğin, 10 saniye)
        time.sleep(10)

@app.route('/anomalies')
def anomalies():
    with sqlite3.connect('alarm_data.db', check_same_thread=False) as conn_alarm:
        cursor_alarm = conn_alarm.cursor()
        cursor_alarm.execute('SELECT * FROM alarms ORDER BY anomaly_time DESC')
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

    # Grafik dosya adını döndüren fonksiyonu çağır
    minute_wise_alarm_graph_file = generate_minute_wise_alarm_graph()
    alarm_type_distribution_chart_file = generate_alarm_type_distribution_chart()
    last_minute_alarm_count = get_last_minute_alarm_count()

    return render_template('anomalies.html', alarm_messages=alarm_messages, minute_wise_alarm_graph_file=minute_wise_alarm_graph_file, alarm_type_distribution_chart_file=alarm_type_distribution_chart_file, last_minute_alarm_count=last_minute_alarm_count)























@app.route('/')
def index():

     # Birinci grafik dosyasını oluştur ve adını al
    packet_count_graph_filename = generate_packet_count_graph()
    # İkinci grafik dosyasını oluştur ve adını al
    protocol_distribution_graph_filename = generate_protocol_distribution_graph()
    # Üçüncü grafik dosyasını oluştur ve adını al
    ethernet_frame_count_graph_filename = generate_ethernet_frame_count_graph()
    # Dördüncü grafik dosyasını oluştur ve adını al
    mac_address_packet_count_graph_filename = generate_mac_address_packet_count_graph()
    # Beşinci grafik dosyasını oluştur ve adını al
    port_usage_graph_filename=generate_port_usage_graph()

    # Yedinci grafik dosyasını oluştur ve adını al
    packet_size_distribution_graph_filename=generate_packet_size_distribution_graph()


    last_20_packets = get_last_20_packets()

    conn_alarm = sqlite3.connect('alarm_data.db', check_same_thread=False)
    cursor_alarm = conn_alarm.cursor()
    cursor_alarm.execute('SELECT id, message, alarm_type, score, anomaly_time FROM alarms')
    alarm_messages = [{'id': row[0], 'message': row[1], 'alarm_type': row[2], 'score': row[3], 'anomaly_time': row[4]} for row in cursor_alarm.fetchall()]
    cursor_alarm.close()
    conn_alarm.close()

    # Şablon dosyasına grafik dosyalarının adını ileterek HTML sayfasını oluştur
    return render_template('index.html', anomaly_messages=alarm_messages,
                           packet_count_graph_filename=packet_count_graph_filename,
                           protocol_distribution_graph_filename=protocol_distribution_graph_filename,
                           ethernet_frame_count_graph_filename=ethernet_frame_count_graph_filename,
                           mac_address_packet_count_graph_filename=mac_address_packet_count_graph_filename,
                           port_usage_graph_filename=port_usage_graph_filename,
                           packet_size_distribution_graph_filename=packet_size_distribution_graph_filename,
                           alarm_messages=alarm_messages,
                           last_20_packets=last_20_packets
                           )



# Ana uygulama çalıştırma noktası
if __name__ == "__main__":
    # Packet Sniffer thread'i başlat
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()
    # Veritabanı işlemleri için bir thread başlat
    data_processing_thread = threading.Thread(target=process_packet_data)
    data_processing_thread.start()
    # Flask uygulamasını çalıştır
    app.run(debug=True)
