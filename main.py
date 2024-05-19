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

# Ana veritabanı bağlantısı
conn_main = sqlite3.connect('packet_data_main.db', check_same_thread=False)
cursor_main = conn_main.cursor()

# Yeni tabloyu oluştur
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


# Değişiklikleri kaydet
conn_main.commit()

#Paket yakalama işlemini başlat
def start_packet_capture():
    def sniff_ethernet_frames():
        sniff(prn=handle_ethernet_frame, store=0, filter="ether")

    # Sniffing işlemini gerçekleştirecek olan thread
    sniff_thread = threading.Thread(target=sniff_ethernet_frames)
    sniff_thread.start()



# Sniffing işlemini gerçekleştirecek olan thread
def packet_sniffer():
    start_packet_capture()

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(cursor, conn, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size=None):
    cursor.execute('''
        INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, packet_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size))
    conn.commit()

# Ethernet çerçevesi işleme fonksiyonu
def handle_ethernet_frame(frame):
    # Ethernet çerçevesinin başlığını analiz et
    dst_mac = frame.dst
    src_mac = frame.src
    eth_type = frame.type

    # Zaman damgasını al
    timestamp = datetime.now()
    packet_size = len(frame.payload) if frame.payload else 0
    # Diğer paket işleme fonksiyonlarına ilet
    handle_ip_packet(frame.payload, timestamp, dst_mac, src_mac, eth_type, packet_size)

    # Protokolü Ethernet olarak işaretle
    handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac, packet_size=packet_size)

    # Veritabanına paketi ekle
    add_packet_to_db(cursor_main, conn_main, timestamp, dst_mac, src_mac, None, None, None, None, "Ethernet",packet_size=packet_size)
# IP paketi işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type, packet_size):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac, "IP", packet_size=packet_size)
        else:
            # IP paketi yoksa sadece Ethernet çerçevesini işle
            handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac, packet_size=packet_size)

# Transport katmanı paketi işleme fonksiyonu
def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac, ip_protocol, packet_size):
    if transport_layer_packet.haslayer(TCP):
        # TCP paketini işle
        tcp_packet = transport_layer_packet[TCP]
        src_port = tcp_packet.sport
        dst_port = tcp_packet.dport
        tcp_packet_size = len(tcp_packet)
        handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac, packet_size=tcp_packet_size)
    elif transport_layer_packet.haslayer(UDP):
        # UDP paketini işle
        udp_packet = transport_layer_packet[UDP]
        src_port = udp_packet.sport
        dst_port = udp_packet.dport
        udp_packet_size = len(udp_packet)
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac, packet_size=udp_packet_size)
    elif transport_layer_packet.haslayer(ICMP):
        # ICMP paketini işle
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac, packet_size=None)
    else:
        # Diğer paket türlerini işle
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac, packet_size=None)

# Paketi işleme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac, packet_size):

    # Eğer kaynak IP veya hedef IP yoksa veya kaynak port veya hedef port yoksa, bu durumları boş bir değerle değiştir
    src_ip = src_ip if src_ip else "Unknown"
    dst_ip = dst_ip if dst_ip else "Unknown"
    src_port = src_port if src_port else "Unknown"
    dst_port = dst_port if dst_port else "Unknown"

    # Veritabanına paketi ekle
    add_packet_to_db(cursor_main, conn_main, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_size)



def generate_packet_count_graph(threshold_value=20):
    # Grafik dosyasının adını sabit tut
    packet_count_graph_filename = 'packet_count_graph.png'

    # Grafik dosyasının yolunu belirle
    graph_path = os.path.join('static', packet_count_graph_filename)

    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 10 saniyedeki verileri al
        ten_seconds_ago = datetime.now() - timedelta(seconds=30)
        cursor.execute('''
            SELECT timestamp FROM packets WHERE timestamp >= ?
        ''', (ten_seconds_ago,))
        rows = cursor.fetchall()

        # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
        timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

        # Zaman aralığını saniyeye dönüştür
        num_seconds = 30

        # Paket sayılarını saniyeye göre grupla
        packet_counts = [0] * (num_seconds + 1)  # Liste boyutunu bir artırarak saniye sayısına uygun hale getir
        for timestamp in timestamps:
            second_index = int(timestamp - ten_seconds_ago.timestamp())
            packet_counts[second_index] += 1

        # Eşik değerini aşan paket sayılarını bul
        over_threshold_indices = [i for i, count in enumerate(packet_counts) if count >= threshold_value]

        # Grafik oluştur
        plt.plot(range(num_seconds + 1), packet_counts, color='blue')  # Liste boyutuna uygun şekilde ayarla ve mavi renkte çiz
        plt.axhline(y=threshold_value, color='red', linestyle='--', label='Threshold')  # Eşik değerini çiz
        for index in over_threshold_indices:
            plt.fill_between([index, index + 1], [packet_counts[index], packet_counts[index]], threshold_value, color='red', alpha=0.3)  # Eşik değerini aşan alanı kırmızıyla doldur
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packets per second')
        plt.title('Packet Count Over Time')
        plt.grid(True)
        plt.legend()  # Eşik değerinin gösterilmesi için bir açıklama ekleyin

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', packet_count_graph_filename)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return packet_count_graph_filename  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()
# İkinci grafik oluşturma fonksiyonu
def generate_protocol_distribution_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 10 saniyedeki verileri al
        thirty_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT protocol, COUNT(*) FROM packets WHERE timestamp >= ? GROUP BY protocol
        ''', (thirty_seconds_ago,))
        rows = cursor.fetchall()

        # Verileri işle ve protokol oranlarını hesapla
        protocols = [row[0] for row in rows]
        counts = [row[1] for row in rows]

        # Grafik oluştur
        plt.figure(figsize=(8, 6))
        plt.bar(protocols, counts, color='skyblue')
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.title('Packet Count by Protocol in Last 30 Seconds')
        plt.xticks(rotation=45)  # Protokol isimlerini 45 derece döndür
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        protocol_distribution_graph = 'protocol_distribution_graph.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', protocol_distribution_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return protocol_distribution_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()

# Üçüncü grafik oluşturma fonksiyonu
def generate_ethernet_frame_count_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data_main.db', check_same_thread=False)
    cursor = conn.cursor()

    try:
        # Son 10 saniyedeki verileri al
        ten_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT timestamp FROM packets WHERE timestamp >= ? AND protocol = "Ethernet"
        ''', (ten_seconds_ago,))
        rows = cursor.fetchall()

        # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
        timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

        # Zaman aralığını saniyeye dönüştür
        num_seconds = 10

        # Ethernet çerçevelerinin sayısını saniyeye göre grupla
        ethernet_frame_counts = [0] * (num_seconds + 1)  # Liste boyutunu bir artırarak saniye sayısına uygun hale getir
        for timestamp in timestamps:
            second_index = int(timestamp - ten_seconds_ago.timestamp())
            ethernet_frame_counts[second_index] += 1

        # Grafik oluştur
        plt.plot(range(num_seconds + 1), ethernet_frame_counts)  # Liste boyutuna uygun şekilde ayarla
        plt.xlabel('Time (seconds)')
        plt.ylabel('Ethernet Frames per second')
        plt.title('Ethernet Frame Count Over Time')
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        ethernet_frame_count_graph = 'ethernet_frame_count_graph.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', ethernet_frame_count_graph)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
        plt.close()
        return ethernet_frame_count_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
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
        cursor_main.execute('''
            SELECT * FROM packets
        ''')
        rows = cursor_main.fetchall()
        if len(rows) > 0:  # Eğer satır varsa devam et
            columns = ['id','timestamp', 'destination_mac', 'source_mac', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'packet_size']

            packet_data = pd.DataFrame(rows, columns=columns)
            return packet_data
        else:
            return pd.DataFrame()  # Eğer satır yoksa boş bir DataFrame döndür
    except Exception as e:
        print("Error fetching packet data:", e)
        return None

def perform_statistical_analysis(packet_data):
    try:
        if packet_data is not None:
            # İstatistiksel analizi gerçekleştirin, örneğin paket boyutlarına göre anomalileri tespit edin
            anomalies, alarm_messages = anomaly_detection_model.statistical_analysis(packet_data)
            return anomalies, alarm_messages
        else:
            # Paket verisi alınamadı, boş döndür
            print("Packet data is None. Statistical analysis cannot be performed.")
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

class AnomalyDetectionModel:
    def __init__(self):
        self.baseline = None
        self.establish_baseline()  # establish_baseline metodunu çağırın

    def establish_baseline(self):  # Argüman beklemeyecek şekilde tanımlanmış
        # Baseline değerlerini kur
        self.baseline = {
            'mean_packet_size': 1500,  # Sabit ortalama
            'std_packet_size': 100      # Sabit standart sapma
        }

    def calculate_risk_score(self, packet_size):
        # Eşik değeri aşan paketler için risk skoru belirleme fonksiyonu
        threshold = 1500  # Örnek eşik değeri
        if packet_size > threshold:
            # Eşik değeri aşan paketler için bir risk skalası kullanarak dinamik olarak bir risk skoru belirle
            scaled_score = 1 + (packet_size - threshold) / 100  # Örnek bir skalaya göre risk skoru hesaplama
            return min(10, int(scaled_score))  # Risk skorunu en fazla 10 olarak sınırlandır
        else:
            # Eşik değeri aşmayan paketler için sabit bir risk skoru kullan
            return 1  # Örnek olarak en düşük risk skoru olan 1'i kullan

    def statistical_analysis(self, data):
        anomalies = pd.DataFrame(columns=data.columns)
        alarm_messages = []

        for index, row in data.iterrows():
            packet_size = row['packet_size']

            # Sabit ortalama ve standart sapma değerlerini al
            mean_packet_size = self.baseline['mean_packet_size']
            std_packet_size = self.baseline['std_packet_size']

            # Z skoru hesapla
            z_score = (packet_size - mean_packet_size) / std_packet_size

            # Risk derecesini hesapla
            risk_score = self.calculate_risk_score(packet_size)

            # Eğer paket boyutu ortalamanın üstündeyse alarm üret
            if packet_size > mean_packet_size:
                initiator_ip = row['source_ip']
                application_id = row['protocol']
                transferred_bytes = packet_size
                timestamp = pd.to_datetime(row['timestamp']).strftime('%d %b %Y, %H:%M')  # Format timestamp
                anomaly_message = f"Initiator IP {initiator_ip}, while using {application_id}, " \
                                  f"transferred {transferred_bytes} bytes at around {timestamp}. " \
                                  f"The mean for this same capture interface + time + IP initiator + " \
                                  f"application ID combination is {mean_packet_size} bytes. " \
                                  f"That degree of deviation from the mean gets a score of {risk_score:.2f}."

                alarm = {
                    'message': anomaly_message,
                    'alarm_type': 'Overflow Alarm',  # Örnek olarak 'Overflow Alarm' kullanıldı
                    'score': risk_score,
                    'anomaly_time': timestamp
                }

                alarm_messages.append(alarm)
                anomalies = pd.concat([anomalies, row.to_frame().T], ignore_index=True)
        return anomalies, alarm_messages
# Modeli oluştur
anomaly_detection_model = AnomalyDetectionModel()

# Alarm mesajlarını kaydetme fonksiyonu
def save_alarms_to_db(alarm_messages):
    for alarm in alarm_messages:
        cursor_alarm.execute('''
            INSERT INTO alarms (message, alarm_type, score, anomaly_time)
            VALUES (?, ?, ?, ?)
        ''', (alarm['message'], alarm['alarm_type'], alarm['score'], alarm['anomaly_time']))
    conn_alarm.commit()
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
            save_data_to_database(anomalies, alarm_messages)

        # Belirli bir süre bekle (örneğin, 5 dakika)
        time.sleep(10)  # 5 dakika bekleyin (300 saniye)
@app.route('/anomalies')
def anomalies():
    # Veritabanından alarm mesajlarını al
    cursor_alarm.execute('''
        SELECT message, alarm_type, score, anomaly_time FROM alarms
    ''')
    alarm_messages = [{'message': row[0], 'alarm_type': row[1], 'score': row[2], 'anomaly_time': row[3]} for row in cursor_alarm.fetchall()]

    # anomalies.html şablon dosyasını kullanarak alarm mesajlarını göster
    return render_template('anomalies.html', anomaly_messages=alarm_messages)
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

    # Şablon dosyasına grafik dosyalarının adını ileterek HTML sayfasını oluştur
    return render_template('index.html', anomaly_messages=alarm_messages,
                           packet_count_graph_filename=packet_count_graph_filename,
                           protocol_distribution_graph_filename=protocol_distribution_graph_filename,
                           ethernet_frame_count_graph_filename=ethernet_frame_count_graph_filename,
                           mac_address_packet_count_graph_filename=mac_address_packet_count_graph_filename
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
