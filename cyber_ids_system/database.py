import mysql.connector
from mysql.connector import Error
from datetime import datetime

# Database Configuration
# NOTE: Update these credentials if your MySQL setup is different
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '172004',  # Default XAMPP/WAMP password is empty
    # 'database': 'cyber_ids' # We connect without DB first to create it
}

def get_connection(with_db=True):
    """Creates a connection to the MySQL database."""
    try:
        config = DB_CONFIG.copy()
        if with_db:
            config['database'] = 'cyber_ids'
        
        connection = mysql.connector.connect(**config)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"❌ Error connecting to MySQL: {e}")
        return None

def init_db():
    """Initializes the database and tables."""
    print("⚙️ Initializing MySQL Database...")
    
    # 1. Create Database if not exists
    conn = get_connection(with_db=False)
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("CREATE DATABASE IF NOT EXISTS cyber_ids")
            print("   - Database 'cyber_ids' checked/created.")
            cursor.close()
            conn.close()
        except Error as e:
            print(f"   - Failed to create database: {e}")
            return

    # 2. Create Tables
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Traffic Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME,
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    protocol VARCHAR(20),
                    service VARCHAR(20),
                    prediction VARCHAR(50),
                    confidence FLOAT,
                    threat_level VARCHAR(20),
                    is_blocked BOOLEAN
                )
            """)
            print("   - Table 'traffic_logs' checked/created.")

            # Blocked IPs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE,
                    blocked_at DATETIME,
                    reason VARCHAR(255)
                )
            """)
            print("   - Table 'blocked_ips' checked/created.")
            
            cursor.close()
            conn.close()
            print("✅ Database initialization complete.")
        except Error as e:
            print(f"❌ Error creating tables: {e}")

def log_traffic(log_entry):
    """Inserts a traffic log entry into the database."""
    # print("DEBUG: Attempting to log traffic...")
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            sql = """INSERT INTO traffic_logs 
                     (timestamp, src_ip, dst_ip, protocol, service, prediction, confidence, threat_level, is_blocked) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            val = (
                log_entry['timestamp'],
                log_entry['src_ip'],
                log_entry['dst_ip'],
                log_entry['protocol'],
                log_entry['service'],
                log_entry['prediction'],
                log_entry['confidence'],
                log_entry['threat_level'],
                log_entry['blocked']
            )
            cursor.execute(sql, val)
            conn.commit()
            cursor.close()
            conn.close()
            # print("DEBUG: Traffic logged successfully.")
        except Error as e:
            print(f"⚠️ Failed to log traffic: {e}")
    else:
        print("DEBUG: Failed to get DB connection in log_traffic")

def block_ip(ip_address, reason="Malicious Activity"):
    """Adds an IP to the blocklist."""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            sql = "INSERT IGNORE INTO blocked_ips (ip_address, blocked_at, reason) VALUES (%s, %s, %s)"
            val = (ip_address, datetime.now(), reason)
            cursor.execute(sql, val)
            conn.commit()
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to block IP: {e}")

def get_recent_logs(limit=10):
    """Fetches the most recent traffic logs."""
    conn = get_connection()
    logs = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(f"SELECT * FROM traffic_logs ORDER BY id DESC LIMIT {limit}")
            results = cursor.fetchall()
            
            # Convert datetime to string for JSON serialization
            for row in results:
                row['timestamp'] = row['timestamp'].isoformat() if row['timestamp'] else ""
                logs.append(row)
                
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to fetch logs: {e}")
    return logs

def get_all_logs(limit=100):
    """Fetches traffic logs for the database viewer."""
    conn = get_connection()
    logs = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(f"SELECT * FROM traffic_logs ORDER BY id DESC LIMIT {limit}")
            results = cursor.fetchall()
            
            for row in results:
                row['timestamp'] = row['timestamp'].isoformat() if row['timestamp'] else ""
                logs.append(row)
                
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to fetch logs: {e}")
    return logs

def get_blocked_ips_details():
    """Fetches all blocked IPs with details."""
    conn = get_connection()
    ips = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
            results = cursor.fetchall()
            
            for row in results:
                row['blocked_at'] = row['blocked_at'].isoformat() if row['blocked_at'] else ""
                ips.append(row)
                
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to fetch blocked IPs: {e}")
    return ips

def get_blocked_ips():
    """Fetches just the list of blocked IP addresses (for the firewall)."""
    conn = get_connection()
    ips = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM blocked_ips ORDER BY blocked_at DESC")
            results = cursor.fetchall()
            ips = [row[0] for row in results]
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to fetch blocked IPs: {e}")
    return ips

def get_stats():
    """Fetches statistics from the database."""
    # print("DEBUG: Fetching stats...")
    conn = get_connection()
    stats = {
        'total_traffic': 0,
        'malicious_count': 0,
        'blocked_count': 0,
        'threat_distribution': {}
    }
    if conn:
        try:
            cursor = conn.cursor()
            
            # Total Traffic
            cursor.execute("SELECT COUNT(*) FROM traffic_logs")
            stats['total_traffic'] = cursor.fetchone()[0]
            # print(f"DEBUG: Total traffic fetched: {stats['total_traffic']}")
            
            # Malicious Count
            cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE prediction != 'Normal'")
            stats['malicious_count'] = cursor.fetchone()[0]
            
            # Blocked Count
            cursor.execute("SELECT COUNT(*) FROM blocked_ips")
            stats['blocked_count'] = cursor.fetchone()[0]
            
            # Threat Distribution
            cursor.execute("SELECT prediction, COUNT(*) FROM traffic_logs GROUP BY prediction")
            results = cursor.fetchall()
            for row in results:
                stats['threat_distribution'][row[0]] = row[1]
                
            cursor.close()
            conn.close()
        except Error as e:
            print(f"⚠️ Failed to fetch stats: {e}")
    else:
        print("DEBUG: Failed to get DB connection in get_stats")
    return stats
