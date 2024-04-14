import socket
import sqlite3
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from flask import Flask, render_template, url_for
from datetime import datetime, timedelta
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

# İkincil veritabanı bağlantısı
conn_secondary = sqlite3.connect('packet_data_secondary.db', check_same_thread=False)
cursor_secondary = conn_secondary.cursor()

# Veritabanı tablolarını oluştur
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
        protocol TEXT
    )
''')
conn_main.commit()

# İkincil veritabanı tablolarını oluştur
cursor_secondary.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        destination_mac TEXT,
        source_mac TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT
    )
''')
conn_secondary.commit()

cursor_secondary.execute('''
    CREATE TABLE IF NOT EXISTS ethernet_packets (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        type INTEGER,
        destination_mac TEXT,
        source_mac TEXT
    )
''')
conn_secondary.commit()

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(cursor, conn, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
    cursor.execute('''
        INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol))
    conn.commit()

# Ethernet çerçevesi işleme fonksiyonu
def handle_ethernet_frame(frame):
    # Ethernet çerçevesinin başlığını analiz et
    dst_mac = frame.dst
    src_mac = frame.src
    eth_type = frame.type

    # Zaman damgasını al
    timestamp = datetime.now()

    # Diğer paket işleme fonksiyonlarına ilet
    handle_ip_packet(frame.payload, timestamp, dst_mac, src_mac, eth_type)

    # Protokolü Ethernet olarak işaretle
    handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac)

    # İkincil veritabanına da ekleyelim
    cursor_secondary.execute('''
        INSERT INTO ethernet_packets (timestamp, type, destination_mac, source_mac)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, None, dst_mac, src_mac))
    conn_secondary.commit()

# IP paketi işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac, "IP")
        else:
            # IP paketi yoksa sadece Ethernet çerçevesini işle
            handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac)

# Transport katmanı paketi işleme fonksiyonu
def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac, ip_protocol):
    if transport_layer_packet.haslayer(TCP):
        # TCP paketini işle
        tcp_packet = transport_layer_packet[TCP]
        src_port = tcp_packet.sport
        dst_port = tcp_packet.dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(UDP):
        # UDP paketini işle
        udp_packet = transport_layer_packet[UDP]
        src_port = udp_packet.sport
        dst_port = udp_packet.dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(ICMP):
        # ICMP paketini işle
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac)
    else:
        # Diğer paket türlerini işle
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac)

# Eş zamanlı akışları saklamak için bir sözlük
concurrent_streams = {}

# Eş zamanlı akış sayısını güncelleyen fonksiyon
def update_concurrent_streams(src_ip, dst_ip, src_port, dst_port):
    stream_id = (src_ip, dst_ip, src_port, dst_port)
    concurrent_streams[stream_id] = concurrent_streams.get(stream_id, 0) + 1

# Eş zamanlı akış sayısını azaltan fonksiyon
def decrease_concurrent_streams(src_ip, dst_ip, src_port, dst_port):
    stream_id = (src_ip, dst_ip, src_port, dst_port)
    if concurrent_streams[stream_id] > 0:
        concurrent_streams[stream_id] -= 1


# Eş zamanlı akış sayısını hesaplayan fonksiyon
def calculate_concurrent_streams():
    while True:
        print("Concurrent Streams:", len(concurrent_streams))
        time.sleep(10)  # Her 10 saniyede bir güncelle

# Paketi işleme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac):
    # Eş zamanlı akış sayısını güncelle
    update_concurrent_streams(src_ip, dst_ip, src_port, dst_port)

    # Eğer kaynak IP veya hedef IP yoksa veya kaynak port veya hedef port yoksa, bu durumları boş bir değerle değiştir
    src_ip = src_ip if src_ip else "Unknown"
    dst_ip = dst_ip if dst_ip else "Unknown"
    src_port = src_port if src_port else "Unknown"
    dst_port = dst_port if dst_port else "Unknown"

    # Paketin özelliklerini yazdır
    #print(f"Timestamp: {timestamp}, Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}")

    # Veritabanına paketi ekle
    add_packet_to_db(cursor_main, conn_main, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol)



# Eş zamanlı akışları grafikleştiren fonksiyon
def plot_concurrent_streams():
    while True:
        # Grafik oluştur
        plt.figure(figsize=(10, 6))
        # Anahtarları tuple'a dönüştürerek kullan
        plt.plot([str(key) for key in concurrent_streams.keys()], list(concurrent_streams.values()), color='skyblue')
        plt.xlabel('Time')
        plt.ylabel('Concurrent Streams')
        plt.title('Concurrent Streams Over Time')
        plt.xticks(rotation=45)
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        concurrent_streams_graph_filename = 'concurrent_streams_graph.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', concurrent_streams_graph_filename)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)

        time.sleep(10)    # Her 10 sanyede bir güncelle
# Eşzamanlı akış sayısını hesaplayan ve grafikleştiren thread'leri başlat
concurrent_streams_thread = threading.Thread(target=calculate_concurrent_streams)
concurrent_streams_thread.start()

plot_concurrent_streams_thread = threading.Thread(target=plot_concurrent_streams)
plot_concurrent_streams_thread.start()
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

# Eski verileri düzenli olarak ikincil veritabanına aktaracak olan thread
def transfer_data_thread():
    while True:
        transfer_old_data()
        # Her gün kontrol et
        time.sleep(24 * 60 * 60)

# Eski verileri ikincil veritabanına aktarma fonksiyonu
def transfer_old_data():
    # ...
    # İkincil veritabanı için tablonun oluşturulup oluşturulmadığını kontrol et
    cursor_secondary.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            destination_mac TEXT,
            source_mac TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT
        )
    ''')
    conn_secondary.commit()
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
        ten_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT timestamp FROM packets WHERE timestamp >= ?
        ''', (ten_seconds_ago,))
        rows = cursor.fetchall()

        # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
        timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

        # Zaman aralığını saniyeye dönüştür
        num_seconds = 10

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

        return mac_address_packet_count_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()

# Ana sayfa
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
    concurrent_streams_graph_filename = 'concurrent_streams_graph.png'  # Concurrent streams grafik dosyasının adını belirt

    # Şablon dosyasına grafik dosyalarının adını ileterek HTML sayfasını oluştur
    return render_template('index.html', packet_count_graph_filename=packet_count_graph_filename,
                           protocol_distribution_graph_filename=protocol_distribution_graph_filename,
                           ethernet_frame_count_graph_filename=ethernet_frame_count_graph_filename,
                           mac_address_packet_count_graph_filename=mac_address_packet_count_graph_filename,
                           concurrent_streams_graph_filename=concurrent_streams_graph_filename)

# Ana uygulama çalıştırma noktası
if __name__ == "__main__":
    # Packet Sniffer thread'i başlat
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    # Veri aktarımı thread'ini başlat
    transfer_thread = threading.Thread(target=transfer_data_thread)
    transfer_thread.start()

    # Concurrent Streams grafik oluşturma thread'ini başlat
    plot_concurrent_streams_thread = threading.Thread(target=plot_concurrent_streams)
    plot_concurrent_streams_thread.start()

    # Flask uygulamasını çalıştır
    app.run(debug=True)
"""
import sqlite3
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from flask import Flask, render_template, url_for
from datetime import datetime, timedelta
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

# İkincil veritabanı bağlantısı
conn_secondary = sqlite3.connect('packet_data_secondary.db', check_same_thread=False)
cursor_secondary = conn_secondary.cursor()

# Veritabanı tablolarını oluştur
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
        protocol TEXT
    )
''')
conn_main.commit()

# İkincil veritabanı tablolarını oluştur
cursor_secondary.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        destination_mac TEXT,
        source_mac TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT
    )
''')
conn_secondary.commit()

cursor_secondary.execute('''
    CREATE TABLE IF NOT EXISTS ethernet_packets (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        type INTEGER,
        destination_mac TEXT,
        source_mac TEXT
    )
''')
conn_secondary.commit()

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(cursor, conn, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
    cursor.execute('''
        INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol))
    conn.commit()

# Ethernet çerçevesi işleme fonksiyonu
def handle_ethernet_frame(frame):
    # Ethernet çerçevesinin başlığını analiz et
    dst_mac = frame.dst
    src_mac = frame.src
    eth_type = frame.type

    # Zaman damgasını al
    timestamp = datetime.now()

    # Diğer paket işleme fonksiyonlarına ilet
    handle_ip_packet(frame.payload, timestamp, dst_mac, src_mac, eth_type)

    # Protokolü Ethernet olarak işaretle
    handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac)

    # İkincil veritabanına da ekleyelim
    cursor_secondary.execute('''
        INSERT INTO ethernet_packets (timestamp, type, destination_mac, source_mac)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, None, dst_mac, src_mac))
    conn_secondary.commit()

# IP paketi işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac, "IP")
        else:
            # IP paketi yoksa sadece Ethernet çerçevesini işle
            handle_packet(None, None, None, None, "Ethernet", timestamp, dst_mac, src_mac)

# Transport katmanı paketi işleme fonksiyonu
def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac, ip_protocol):
    if transport_layer_packet.haslayer(TCP):
        # TCP paketini işle
        tcp_packet = transport_layer_packet[TCP]
        src_port = tcp_packet.sport
        dst_port = tcp_packet.dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(UDP):
        # UDP paketini işle
        udp_packet = transport_layer_packet[UDP]
        src_port = udp_packet.sport
        dst_port = udp_packet.dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(ICMP):
        # ICMP paketini işle
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac)
    else:
        # Diğer paket türlerini işle
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac)

# Eş zamanlı akışları saklamak için bir sözlük
concurrent_streams = {}

# Eş zamanlı akış sayısını güncelleyen fonksiyon
def update_concurrent_streams(src_ip, dst_ip, src_port, dst_port):
    stream_id = (src_ip, dst_ip, src_port, dst_port)
    concurrent_streams[stream_id] = concurrent_streams.get(stream_id, 0) + 1

# Eş zamanlı akış sayısını azaltan fonksiyon
def decrease_concurrent_streams(src_ip, dst_ip, src_port, dst_port):
    stream_id = (src_ip, dst_ip, src_port, dst_port)
    if concurrent_streams[stream_id] > 0:
        concurrent_streams[stream_id] -= 1

# Eş zamanlı akış sayısını hesaplayan fonksiyon
def calculate_concurrent_streams():
    while True:
        print("Concurrent Streams:", len(concurrent_streams))
        time.sleep(10)  # Her 10 saniyede bir güncelle

# Paketi işleme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac):
    # Eş zamanlı akış sayısını güncelle
    update_concurrent_streams(src_ip, dst_ip, src_port, dst_port)

    # Eğer kaynak IP veya hedef IP yoksa veya kaynak port veya hedef port yoksa, bu durumları boş bir değerle değiştir
    src_ip = src_ip if src_ip else "Unknown"
    dst_ip = dst_ip if dst_ip else "Unknown"
    src_port = src_port if src_port else "Unknown"
    dst_port = dst_port if dst_port else "Unknown"

    # Paketin özelliklerini yazdır
    print(f"Timestamp: {timestamp}, Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}")

    # Veritabanına paketi ekle
    add_packet_to_db(cursor_main, conn_main, timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol)

# Eş zamanlı akışları grafikleştiren fonksiyon
def plot_concurrent_streams():
    while True:
        # Grafik oluştur
        plt.figure(figsize=(10, 6))
        plt.plot(list(concurrent_streams.keys()), list(concurrent_streams.values()), color='skyblue')
        plt.xlabel('Time')
        plt.ylabel('Concurrent Streams')
        plt.title('Concurrent Streams Over Time')
        plt.xticks(rotation=45)
        plt.grid(True)

        # Grafik dosyasının adını sabit tut
        concurrent_streams_graph_filename = 'concurrent_streams_graph.png'

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', concurrent_streams_graph_filename)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)

        time.sleep(10)  # Her 1 dakikada bir güncelle

# Eşzamanlı akış sayısını hesaplayan ve grafikleştiren thread'leri başlat
concurrent_streams_thread = threading.Thread(target=calculate_concurrent_streams)
concurrent_streams_thread.start()

plot_concurrent_streams_thread = threading.Thread(target=plot_concurrent_streams)
plot_concurrent_streams_thread.start()
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

# Eski verileri düzenli olarak ikincil veritabanına aktaracak olan thread
def transfer_data_thread():
    while True:
        transfer_old_data()
        # Her gün kontrol et
        time.sleep(24 * 60 * 60)

# Eski verileri ikincil veritabanına aktarma fonksiyonu
def transfer_old_data():
    # ...
    # İkincil veritabanı için tablonun oluşturulup oluşturulmadığını kontrol et
    cursor_secondary.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            destination_mac TEXT,
            source_mac TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT
        )
    ''')
    conn_secondary.commit()
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
        ten_seconds_ago = datetime.now() - timedelta(seconds=10)
        cursor.execute('''
            SELECT timestamp FROM packets WHERE timestamp >= ?
        ''', (ten_seconds_ago,))
        rows = cursor.fetchall()

        # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
        timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

        # Zaman aralığını saniyeye dönüştür
        num_seconds = 10

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

        return mac_address_packet_count_graph  # Grafik dosya adını döndür
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()

# Ana sayfa
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
    concurrent_streams_graph_filename = 'concurrent_streams_graph.png'  # Concurrent streams grafik dosyasının adını belirt

    # Şablon dosyasına grafik dosyalarının adını ileterek HTML sayfasını oluştur
    return render_template('index.html', packet_count_graph_filename=packet_count_graph_filename,
                           protocol_distribution_graph_filename=protocol_distribution_graph_filename,
                           ethernet_frame_count_graph_filename=ethernet_frame_count_graph_filename,
                           mac_address_packet_count_graph_filename=mac_address_packet_count_graph_filename,
                           concurrent_streams_graph_filename=concurrent_streams_graph_filename)

# Ana uygulama çalıştırma noktası
if __name__ == "__main__":
    # Packet Sniffer thread'i başlat
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    # Veri aktarımı thread'ini başlat
    transfer_thread = threading.Thread(target=transfer_data_thread)
    transfer_thread.start()

    # Concurrent Streams grafik oluşturma thread'ini başlat
    plot_concurrent_streams_thread = threading.Thread(target=plot_concurrent_streams)
    plot_concurrent_streams_thread.start()

    # Flask uygulamasını çalıştır
    app.run(debug=True)
"""
