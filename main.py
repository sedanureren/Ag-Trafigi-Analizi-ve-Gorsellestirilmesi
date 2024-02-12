import os

from flask import Flask, render_template, g
import matplotlib.pyplot as plt
import sqlite3
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.all import sniff
import threading
import matplotlib
import seaborn as sns
matplotlib.use('Agg')

app = Flask(__name__)

# Veritabanı bağlantısını açma
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('packet_database.db')
    return db

# Veritabanınızı oluşturan fonksiyon
def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()

        # packets tablosunu oluştur
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                data TEXT,
                timestamp DATETIME,
                size INTEGER
            )
        ''')

        conn.commit()
        conn.close()

# İlk çalıştırmada veritabanını oluştur
init_db()
def init_static_files_table():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()

        # static_files tablosunu oluştur
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS static_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT,
                file_data BLOB
            )
        ''')

        conn.commit()
        conn.close()

# İlk çalıştırmada static_files tablosunu oluştur
init_static_files_table()
# Middleware - Her request için veritabanı bağlantısını aç
@app.before_request
def before_request():
    g.db = get_db()

# Veritabanı bağlantısını kapatma
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def insert_into_db(packet):
    print("Packet captured. Updating database and creating graphs...")

    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        protocol = None
        source_ip = None
        dest_ip = None
        source_port = None
        dest_port = None
        data = None
        timestamp = packet.time
        size = len(packet)

        if IP in packet:
            if packet.haslayer(TCP):
                protocol = 'TCP'
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                if packet[TCP].flags.ACK:
                    data = str(packet[TCP].load)
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
                data = str(packet[UDP].payload)
            elif packet.haslayer(ICMP):  # ICMP paket kontrolü ekleniyor
                protocol = 'ICMP'
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                data = str(packet[ICMP].payload)
            elif ARP in packet:  # Use ARP from scapy.layers.l2
                protocol = 'ARP'
                source_ip = packet[ARP].psrc
                dest_ip = packet[ARP].pdst
                data = packet[ARP].hwsrc  # You may adjust this based on your needs


        # Veritabanına ekleme
        cursor.execute('''INSERT INTO packets 
                          (protocol, source_ip, dest_ip, source_port, dest_port, data, timestamp, size) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (protocol, source_ip, dest_ip, source_port, dest_port, data, timestamp, size))
        conn.commit()

        # Her paket eklendikten sonra grafikleri tekrar oluştur
        create_graphs_after_insert(conn)

        # Veritabanı bağlantısını kapat
        conn.close()
        print("Database updated and graphs created.")



# Her paket eklendikten sonra grafikleri tekrar oluştur
def create_graphs_after_insert(conn):
    source_ip_graph = create_source_ip_graph(conn)
    dest_ip_graph = create_dest_ip_graph(conn)
    tcp_udp_graph = create_tcp_udp_graph(conn)
    packet_size_graph = create_packet_size_graph(conn)
    protocol_distribution_graph = create_protocol_distribution_graph(conn)
    device_count_graph = create_device_count_graph(conn)
    connection_duration_graph = create_device_connection_duration_graph(conn)
    heatmap_path = create_heatmap(conn)


     # Statik dosyaları güncelle
    update_static_images(
        f'static/source_ip_graph.png',
        f'static/dest_ip_graph.png',
        f'static/tcp_udp_graph.png',
        f'static/packet_size_graph.png',
        f'static/protocol_distribution_graph.png',
        f'static/device_count_graph.png',
        f'static/connection_duration_graph.png',
        heatmap_path
    )

    # Her bir grafik için oluşturulan dosya yollarını ekrana bastıralım
    print("Source IP Graph Path:", source_ip_graph)
    print("Dest IP Graph Path:", dest_ip_graph)
    print("TCP UDP Graph Path:", tcp_udp_graph)
    print("Packet Size Graph Path:", packet_size_graph)
    print("Protocol Distribution Graph Path:", protocol_distribution_graph)
    print("Device Count Graph Path:", device_count_graph)
    print("Connection Duration Graph Path:", connection_duration_graph)
    print("Heatmap Path:", heatmap_path)

def update_static_images(source_ip_graph_path, dest_ip_graph_path, tcp_udp_graph_path, packet_size_graph_path, protocol_distribution_graph_path, device_count_graph_path,connection_duration_graph_path,heatmap_path):
    try:
        # Dosyaları veritabanına ekle
        insert_file_into_db(source_ip_graph_path)
        insert_file_into_db(dest_ip_graph_path)
        insert_file_into_db(tcp_udp_graph_path)
        insert_file_into_db(packet_size_graph_path)
        insert_file_into_db(protocol_distribution_graph_path)
        insert_file_into_db(device_count_graph_path)
        insert_file_into_db(connection_duration_graph_path)
        insert_file_into_db(heatmap_path)


    except Exception as e:
        print(f"Statik dosyalar güncellenirken bir hata oluştu: {e}")
    else:
        print("Statik dosyalar başarıyla güncellendi.")





def create_protocol_distribution_graph(conn):
    # TCP, UDP, ICMP ve ARP'yi içeren bir sorgu
    query = "SELECT protocol, COUNT(*) AS count FROM packets WHERE (source_ip IS NULL AND dest_ip IS NULL) OR protocol IN ('ARP', 'ICMP', 'TCP', 'UDP') GROUP BY protocol"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # TCP, UDP, ICMP ve ARP'yi sonuçta bulunmazsa 0 ile ekleyin
    protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
    for protocol in protocols:
        if protocol not in df['protocol'].values:
            protocol_row = pd.DataFrame({'protocol': [protocol], 'count': [0]})
            df = pd.concat([df, protocol_row], ignore_index=True)

    plt.figure(figsize=(6, 6))
    plt.pie(df['count'], labels=df['protocol'], autopct='%1.1f%%', startangle=140, colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99'])
    plt.title('Protokol Dağılımı')

    graph_file_path = 'static/protocol_distribution_graph.png'
    try:
        plt.savefig(graph_file_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return graph_file_path
def create_heatmap(conn):
    query = '''
        SELECT source_ip, dest_ip, COUNT(*) AS count
        FROM packets
        WHERE source_ip IS NOT NULL AND dest_ip IS NOT NULL
        GROUP BY source_ip, dest_ip
    '''
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme
    pivot_df = df.pivot(index='source_ip', columns='dest_ip', values='count').fillna(0)

    # Isı haritası oluşturma
    plt.figure(figsize=(12, 8))
    sns.heatmap(pivot_df, cmap="YlGnBu", annot=True, fmt='g')
    plt.title('Kaynak ve Hedef IP Adresleri Arasındaki Paket Sayısı Isı Haritası')
    plt.xlabel('Hedef IP Adresi')
    plt.ylabel('Kaynak IP Adresi')

    heatmap_file_path = 'static/heatmap.png'
    try:
        plt.savefig(heatmap_file_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return heatmap_file_path
# Zamanla değişen cihaz bağlantı sürelerini gösteren grafik
def create_device_connection_duration_graph(conn):
    query = '''
        SELECT timestamp, source_ip, MIN(timestamp) OVER (PARTITION BY source_ip) AS connection_start_time
        FROM packets
        WHERE source_ip IS NOT NULL
        GROUP BY timestamp, source_ip
    '''
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme (zaman sütunlarını datetime'a çevirme)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df['connection_start_time'] = pd.to_datetime(df['connection_start_time'], unit='s')

    # Bağlantı sürelerini hesapla
    df['connection_duration'] = df['timestamp'] - df['connection_start_time']

    # Grafik oluşturma
    plt.figure(figsize=(10, 6))
    for device_ip, group in df.groupby('source_ip'):
        plt.plot(group['timestamp'], group['connection_duration'], label=device_ip)

    plt.xlabel('Zaman')
    plt.ylabel('Bağlantı Süresi')
    plt.title('Zamanla Değişen Cihaz Bağlantı Süreleri')
    plt.legend(loc='upper left')
    plt.grid(True)

    connection_duration_graph_path = 'static/connection_duration_graph.png'
    try:
        plt.savefig(connection_duration_graph_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return connection_duration_graph_path



# Zamanla değişen cihaz sayısını gösteren grafik
def create_device_count_graph(conn):
    query = "SELECT timestamp, COUNT(DISTINCT source_ip) + COUNT(DISTINCT dest_ip) AS device_count FROM packets WHERE source_ip IS NOT NULL OR dest_ip IS NOT NULL GROUP BY timestamp"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme (zaman sütununu datetime'a çevirme)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

    # Grafik oluşturma
    plt.figure(figsize=(10, 6))
    plt.plot(df['timestamp'], df['device_count'], color='purple')
    plt.xlabel('Zaman')
    plt.ylabel('Cihaz Sayısı')
    plt.title('Zamanla Değişen Cihaz Sayısı')
    plt.grid(True)

    device_count_graph_path = 'static/device_count_graph.png'
    try:
        plt.savefig(device_count_graph_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return device_count_graph_path

# Kaynak IP Adresleri ve Paket Sayıları Grafiği Oluşturma
def create_source_ip_graph(conn):
    query = "SELECT source_ip, COUNT(*) AS count FROM packets WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 30"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    plt.figure(figsize=(6, 4))
    plt.bar(df['source_ip'], df['count'], color='skyblue')
    plt.xlabel('Kaynak IP Adresi')
    plt.ylabel('Paket Sayısı')
    plt.title('En Fazla Kullanılan Kaynak IP Adresleri')
    plt.xticks(rotation=45)
    plt.tight_layout()

    graph_file_path = 'static/source_ip_graph.png'
    try:
        plt.savefig(graph_file_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return graph_file_path

# Hedef IP Adresleri ve Paket Sayıları Grafiği Oluşturma
def create_dest_ip_graph(conn):
    query = "SELECT dest_ip, COUNT(*) AS count FROM packets WHERE dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC LIMIT 30"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    plt.figure(figsize=(6, 4))
    plt.bar(df['dest_ip'], df['count'], color='salmon')
    plt.xlabel('Hedef IP Adresi')
    plt.ylabel('Paket Sayısı')
    plt.title('En Fazla Kullanılan Hedef IP Adresleri')
    plt.xticks(rotation=45)
    plt.tight_layout()

    graph_file_path = 'static/dest_ip_graph.png'
    try:
        plt.savefig(graph_file_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return graph_file_path

# TCP ve UDP paket sayıları değişimini gösteren grafik
def create_tcp_udp_graph(conn):
    query = "SELECT timestamp, protocol FROM packets WHERE protocol='TCP' OR protocol='UDP'"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme (zaman sütununu datetime'a çevirme, gruplama)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    grouped = df.groupby([pd.Grouper(key='timestamp', freq='1s'), 'protocol']).size().unstack(fill_value=0)

    # Grafik oluşturma
    try:
        plt.figure(figsize=(10, 6))
        plt.stackplot(grouped.index, grouped['TCP'], grouped['UDP'], labels=['TCP', 'UDP'])
        plt.xlabel('Zaman')
        plt.ylabel('Paket Sayısı')
        plt.title('TCP ve UDP Paket Sayısı Değişimi')
        plt.legend(loc='upper left')
        plt.grid(True)

        tcp_udp_graph_path = os.path.join('static', 'tcp_udp_graph.png')
        plt.savefig(tcp_udp_graph_path)
        plt.close()
        return tcp_udp_graph_path
    except Exception as e:
        print(f"Grafik oluşturulurken bir hata oluştu: {e}")
        return None

# Zaman göre paket boyutu değişimini gösteren grafik
def create_packet_size_graph(conn):
    query = "SELECT timestamp, size FROM packets"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme (zaman sütununu datetime'a çevirme)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

    # Grafik oluşturma
    plt.figure(figsize=(10, 6))
    plt.plot(df['timestamp'], df['size'], color='green')
    plt.xlabel('Zaman')
    plt.ylabel('Paket Boyutu')
    plt.title('Zaman Göre Paket Boyutu Değişimi')
    plt.grid(True)

    packet_size_graph_path = 'static/packet_size_graph.png'
    try:
        plt.savefig(packet_size_graph_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return packet_size_graph_path
def create_data_ratio_pie_chart(conn):
    # Query to get the sum of sizes for incoming and outgoing data
    query = '''
        SELECT
            SUM(CASE WHEN source_ip IS NOT NULL THEN size ELSE 0 END) AS incoming_data,
            SUM(CASE WHEN dest_ip IS NOT NULL THEN size ELSE 0 END) AS outgoing_data
            FROM packets
            WHERE source_ip IS NOT NULL OR dest_ip IS NOT NULL;
     '''

    df = pd.read_sql_query(query, conn)
    incoming_data = df['incoming_data'].iloc[0]
    outgoing_data = df['outgoing_data'].iloc[0]
    if df.empty:
        return None

    # Veriyi doğrulama için gelen ve giden veriyi yazdırma
    print(f"Gelen Veri: {incoming_data}")
    print(f"Giden Veri: {outgoing_data}")

    # Pasta grafiği oluşturma
    labels = ['Gelen Veri', 'Giden Veri']
    sizes = [incoming_data, outgoing_data]

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#66b3ff', '#99ff99'])
    plt.title('Incoming vs Outgoing Data Ratio')

    graph_file_path = 'static/data_ratio_pie_chart.png'
    try:
        plt.savefig(graph_file_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return graph_file_path

# Zamanla değişen cihaz sayısını gösteren grafik
def create_device_count_graph(conn):
    query = "SELECT timestamp, COUNT(DISTINCT source_ip) + COUNT(DISTINCT dest_ip) AS device_count FROM packets WHERE source_ip IS NOT NULL OR dest_ip IS NOT NULL GROUP BY timestamp"
    df = pd.read_sql_query(query, conn)

    if df.empty:
        return None

    # Veri ön işleme (zaman sütununu datetime'a çevirme)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

    # Grafik oluşturma
    plt.figure(figsize=(10, 6))
    plt.plot(df['timestamp'], df['device_count'], color='purple')
    plt.xlabel('Zaman')
    plt.ylabel('Cihaz Sayısı')
    plt.title('Zamanla Değişen Cihaz Sayısı')
    plt.grid(True)

    device_count_graph_path = 'static/device_count_graph.png'
    try:
        plt.savefig(device_count_graph_path)
    except Exception as e:
        print(f"Grafik dosyası kaydedilirken bir hata oluştu: {e}")
        return None
    else:
        plt.close()
        return device_count_graph_path

# Paket yakalama işlemini başlat
def start_packet_capture():
    sniff(prn=insert_into_db, store=0, filter="icmp or arp or (udp and (port 53 or port 67 or port 68)) or (tcp and (port 80 or port 443))")
# Veritabanına dosyayı eklemek için fonksiyon
def insert_file_into_db(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()

    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()

        # Veritabanına dosyayı ekle
        cursor.execute('''INSERT INTO static_files (file_name, file_data) VALUES (?, ?)''',
                       (file_path.split('/')[-1], sqlite3.Binary(file_data)))
        conn.commit()
        conn.close()

# Her paket eklendikten sonra grafikleri tekrar oluştur
def create_graphs_after_insert(conn):
    source_ip_graph = create_source_ip_graph(conn)
    dest_ip_graph = create_dest_ip_graph(conn)
    tcp_udp_graph = create_tcp_udp_graph(conn)
    packet_size_graph = create_packet_size_graph(conn)
    protocol_distribution_graph = create_protocol_distribution_graph(conn)
    device_count_graph = create_device_count_graph(conn)
    connection_duration_graph = create_device_connection_duration_graph(conn)
    data_ratio_pie_chart = create_data_ratio_pie_chart(conn)
    heatmap_path=create_heatmap(conn)
    # Statik dosyaları güncelle
    update_static_images(
        f'static/source_ip_graph.png',
        f'static/dest_ip_graph.png',
        f'static/tcp_udp_graph.png',
        f'static/packet_size_graph.png',
        f'static/protocol_distribution_graph.png',
        f'static/device_count_graph.png',
        f'static/connection_duration_graph.png',
        heatmap_path
    )
    # Dosyaları veritabanına ekle
    insert_file_into_db('static/source_ip_graph.png')
    insert_file_into_db('static/dest_ip_graph.png')
    insert_file_into_db('static/tcp_udp_graph.png')
    insert_file_into_db('static/packet_size_graph.png')
    insert_file_into_db('static/protocol_distribution_graph.png')
    insert_file_into_db('static/device_count_graph.png')
    insert_file_into_db('static/heatmap.png')

    # Her bir grafik için oluşturulan dosya yollarını ekrana bastıralım
    print("Source IP Graph Path:", source_ip_graph)
    print("Dest IP Graph Path:", dest_ip_graph)
    print("TCP UDP Graph Path:", tcp_udp_graph)
    print("Packet Size Graph Path:", packet_size_graph)
    print("Protocol Distribution Graph Path:", protocol_distribution_graph)
    print("Device Count Graph Path:", device_count_graph)

# Ana sayfa
@app.route('/')
def index():
    conn = get_db()
    # Her sayfa yenilendiğinde grafikleri tekrar oluştur
    device_count_graph =create_device_count_graph(conn)
    source_ip_graph = create_source_ip_graph(conn)
    dest_ip_graph = create_dest_ip_graph(conn)
    tcp_udp_graph = create_tcp_udp_graph(conn)
    packet_size_graph = create_packet_size_graph(conn)
    protocol_distribution_graph = create_protocol_distribution_graph(conn)
    connection_duration_graph = create_device_connection_duration_graph(conn)
    data_ratio_pie_chart = create_data_ratio_pie_chart(conn)
    heatmap=create_heatmap(conn)
    # Veritabanı bağlantısını kapat
    conn.close()
    return render_template('index.html',
                           source_ip_graph=source_ip_graph,
                           dest_ip_graph=dest_ip_graph,
                           tcp_udp_graph=tcp_udp_graph,
                           packet_size_graph=packet_size_graph,
                           protocol_distribution_graph=protocol_distribution_graph,
                           device_count=device_count_graph,
                           connection_duration_graph=connection_duration_graph,
                           data_ratio_pie_chart=data_ratio_pie_chart,
                           heatmap=heatmap,
                           # Her bir grafik için benzersiz bir isim belirleyin
                           source_ip_graph_name='source_ip_graph.png',
                           dest_ip_graph_name='dest_ip_graph.png',
                           tcp_udp_graph_name='tcp_udp_graph.png',
                           packet_size_graph_name='packet_size_graph.png',
                           protocol_distribution_graph_name='protocol_distribution_graph.png',
                           connection_duration_graph_name='connection_duration_graph.png',
                           data_ratio_pie_chart_name='data_ratio_pie_chart.png',
                           heatmap_name='heatmap.png'
                           )

if __name__ == "__main__":
    # Paket yakalama thread'ini başlat
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.start()

    # Flask uygulamasını başlat
    app.run(debug=True,threaded=True)
