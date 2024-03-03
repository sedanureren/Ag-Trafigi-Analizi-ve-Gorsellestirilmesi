"""import sqlite3
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from datetime import datetime

# Veritabanı bağlantısını oluştur
conn = sqlite3.connect('packet_data.db')
cursor = conn.cursor()

# Tablo oluştur (opsiyonel)
cursor.execute('''
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

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
    cursor.execute('''
        INSERT INTO packets (timestamp, destination_mac, source_mac, source_ip, destination_ip, source_port, destination_port, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol))
    conn.commit()

def handle_ethernet_frame(frame):
    # Ethernet çerçevesinin başlığını analiz et
    dst_mac = frame.dst
    src_mac = frame.src
    eth_type = frame.type
    
    # Zaman damgasını ekleyelim
    timestamp = datetime.now()

    # İşlemleri devam ettirmek için diğer paket işleme fonksiyonlarına ilet
    handle_ip_packet(frame.payload, timestamp, dst_mac, src_mac, eth_type)

def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac)

def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac):
    if transport_layer_packet.haslayer(TCP):
        # TCP paketini işle
        src_port = transport_layer_packet[TCP].sport
        dst_port = transport_layer_packet[TCP].dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "TCP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(UDP):
        # UDP paketini işle
        src_port = transport_layer_packet[UDP].sport
        dst_port = transport_layer_packet[UDP].dport
        handle_packet(src_ip, dst_ip, src_port, dst_port, "UDP", timestamp, dst_mac, src_mac)
    elif transport_layer_packet.haslayer(ICMP):
        # ICMP paketini işle
        handle_packet(src_ip, dst_ip, None, None, "ICMP", timestamp, dst_mac, src_mac)
    else:
        # Diğer paket türlerini işle
        handle_packet(src_ip, dst_ip, None, None, "OTHER", timestamp, dst_mac, src_mac)

def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac):
    # Paketi işleme kodu buraya gelecek
    print("Packet captured at:", timestamp)
    print("Destination MAC Address:", dst_mac)
    print("Source MAC Address:", src_mac)
    print("Source IP:", src_ip)
    print("Destination IP:", dst_ip)
    print("Source Port:", src_port)
    print("Destination Port:", dst_port)
    print("Protocol:", protocol)
    print("-----------------------------")

    # Paketi veritabanına ekle
    add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol)

def start_packet_capture():
    sniff(prn=handle_ethernet_frame, store=0)

# Paket yakalama işlemini başlat
start_packet_capture()












"""
"""
import sqlite3
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from flask import Flask, render_template
from datetime import datetime
import threading
import matplotlib.pyplot as plt

app = Flask(__name__)

# Veritabanı bağlantısını oluştur
conn = sqlite3.connect('packet_data.db', check_same_thread=False)
cursor = conn.cursor()

# Tablo oluştur (opsiyonel)
cursor.execute('''
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
conn.commit()

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
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

# IP paketi işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac)

# Transport katmanı paketi işleme fonksiyonu
def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac):
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

# Paketi işleme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac):
    # Paketi işleme kodu buraya gelecek
    add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol)

# Paket yakalama işlemini başlat
def start_packet_capture():
    sniff(prn=handle_ethernet_frame, store=0)

# Sniffing işlemini gerçekleştirecek olan thread
def packet_sniffer():
    start_packet_capture()

# Grafik oluştur
def generate_graph():
    # Yeni bir cursor nesnesi oluştur
    conn = sqlite3.connect('packet_data.db', check_same_thread=False)
    cursor = conn.cursor()

    # Veritabanından verileri al
    cursor.execute('SELECT timestamp FROM packets')
    rows = cursor.fetchall()

    # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

    # Başlangıç ve bitiş zamanlarını belirle
    start_time = min(timestamps)
    end_time = max(timestamps)

    # Zaman aralığını saniyeye dönüştür
    delta = end_time - start_time
    num_seconds = int(delta)

    # Paket sayılarını saniyeye göre grupla
    packet_counts = [0] * (num_seconds + 1)  # Liste boyutunu bir artırarak saniye sayısına uygun hale getir
    for timestamp in timestamps:
        second_index = int(timestamp - start_time)
        packet_counts[second_index] += 1

    # Grafik oluştur
    plt.plot(range(num_seconds + 1), packet_counts)  # Liste boyutuna uygun şekilde ayarla
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packets per second')
    plt.title('Packet Count Over Time')
    plt.grid(True)

    # Grafik dosyasını static klasörüne kaydet
    plt.savefig('static/packet_count.png')
    plt.close()  # Grafik nesnesini kapat

# Ana sayfa için route
@app.route('/')
def index():
    generate_graph()
    return render_template('index.html')

if __name__ == "__main__":
    # Packet Sniffer thread'i başlat
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    # Flask uygulamasını çalıştır
    app.run(debug=True)
"""













import sqlite3
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from flask import Flask, render_template
from datetime import datetime, timedelta
import threading
import matplotlib.pyplot as plt
import os
import time

app = Flask(__name__)

# Veritabanı bağlantısını oluştur
conn = sqlite3.connect('packet_data.db', check_same_thread=False)
cursor = conn.cursor()

# Tablo oluştur (opsiyonel)
cursor.execute('''
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
conn.commit()

# Veritabanına veri eklemek için fonksiyon
def add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
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

# IP paketi işleme fonksiyonu
def handle_ip_packet(packet, timestamp, dst_mac, src_mac, eth_type):
    # Ethernet tipi IPv4 ise işlem yap
    if eth_type == 0x0800:
        if packet.haslayer(IP):
            # IP paketini işle
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            handle_transport_layer(packet[IP].payload, src_ip, dst_ip, timestamp, dst_mac, src_mac)

# Transport katmanı paketi işleme fonksiyonu
def handle_transport_layer(transport_layer_packet, src_ip, dst_ip, timestamp, dst_mac, src_mac):
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

# Paketi işleme fonksiyonu
def handle_packet(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, dst_mac, src_mac):
    # Paketi işleme kodu buraya gelecek
    add_packet_to_db(timestamp, dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, protocol)

# Paket yakalama işlemini başlat
def start_packet_capture():
    sniff(prn=handle_ethernet_frame, store=0)

# Sniffing işlemini gerçekleştirecek olan thread
def packet_sniffer():
    start_packet_capture()
"""
# Grafik oluştur
def generate_graph():
    # Yeni bir cursor nesnesi oluştur
    conn = sqlite3.connect('packet_data.db', check_same_thread=False)
    cursor = conn.cursor()

    # Veritabanından verileri al
    cursor.execute('SELECT timestamp FROM packets')
    rows = cursor.fetchall()

    # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

    # Başlangıç ve bitiş zamanlarını belirle
    start_time = min(timestamps)
    end_time = max(timestamps)

    # Zaman aralığını saniyeye dönüştür
    delta = end_time - start_time
    num_seconds = int(delta)

    # Paket sayılarını saniyeye göre grupla
    packet_counts = [0] * (num_seconds + 1)  # Liste boyutunu bir artırarak saniye sayısına uygun hale getir
    for timestamp in timestamps:
        second_index = int(timestamp - start_time)
        packet_counts[second_index] += 1

    # Grafik oluştur
    plt.plot(range(num_seconds + 1), packet_counts)  # Liste boyutuna uygun şekilde ayarla
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packets per second')
    plt.title('Packet Count Over Time')
    plt.grid(True)

    # Grafik dosyasının ismini oluştur
    graph_filename = 'packet_count_' + str(int(time.time())) + '.png'
    graph_path = os.path.join('static', graph_filename)

    # Grafik dosyasını kaydet
    plt.savefig(graph_path)
    plt.close()  # Grafik nesnesini kapat
    return graph_filename
"""


"""
# Grafik oluştur
def generate_graph():
    # Şu anki zamanı al
    current_time = datetime.now()
    # Son 10 saniyede gelen paketleri almak için 10 saniye öncesinin zamanını hesapla
    ten_seconds_ago = current_time - timedelta(seconds=10)

    # Yeni bir cursor nesnesi oluştur
    conn = sqlite3.connect('packet_data.db', check_same_thread=False)
    cursor = conn.cursor()

    # Veritabanından son 10 saniyedeki paketlerin zaman damgalarını al
    cursor.execute('SELECT timestamp FROM packets WHERE timestamp > ?', (ten_seconds_ago,))
    rows = cursor.fetchall()

    # Zaman damgalarını datetime nesnelerine dönüştür ve saniyeye dönüştür
    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').timestamp() for row in rows]

    # Başlangıç ve bitiş zamanlarını belirle
    start_time = ten_seconds_ago.timestamp()
    end_time = current_time.timestamp()

    # Zaman aralığını saniyeye dönüştür
    delta = end_time - start_time
    num_seconds = int(delta)

    # Paket sayılarını saniyeye göre grupla
    packet_counts = [0] * (num_seconds + 1)  # Liste boyutunu bir artırarak saniye sayısına uygun hale getir
    for timestamp in timestamps:
        second_index = int(timestamp - start_time)
        packet_counts[second_index] += 1

    # Grafik oluştur
    plt.plot(range(num_seconds + 1), packet_counts)  # Liste boyutuna uygun şekilde ayarla
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packets per second')
    plt.title('Packet Count Over Last 10 Seconds')
    plt.grid(True)

    # Grafik dosyasının ismini oluştur
    graph_filename = 'packet_count_' + str(int(time.time())) + '.png'
    graph_path = os.path.join('static', graph_filename)

    # Grafik dosyasını kaydet
    plt.savefig(graph_path)
    plt.close()  # Grafik nesnesini kapat

    # Grafik dosyasının adını döndür
    return graph_filename

"""

# Grafik dosyasının adını sabit bir isim olarak belirle
graph_filename = 'packet_count.png'
# Grafik oluştur
def generate_graph():
    # Yeni bir bağlantı ve imleç oluştur
    conn = sqlite3.connect('packet_data.db', check_same_thread=False)
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

        # Grafik oluştur
        plt.plot(range(num_seconds + 1), packet_counts)  # Liste boyutuna uygun şekilde ayarla
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packets per second')
        plt.title('Packet Count Over Time')
        plt.grid(True)

        # Grafik dosyasının yolunu belirle
        graph_path = os.path.join('static', graph_filename)

        # Grafik dosyasını kaydet
        plt.savefig(graph_path)
    finally:
        # İmleç ve bağlantıyı kapat
        cursor.close()
        conn.close()



@app.route('/')
def index():
    # Grafik dosyasını oluştur
    generate_graph()
    # Şablon dosyasına grafik dosyasının adını ileterek HTML sayfasını oluştur
    return render_template('index.html', graph_filename='packet_count.png')
if __name__ == "__main__":
    # Packet Sniffer thread'i başlat
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    # Flask uygulamasını çalıştır
    app.run(debug=True)








