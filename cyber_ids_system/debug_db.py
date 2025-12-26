import database
import mysql.connector

print("🔍 Debugging Database...")

try:
    conn = database.get_connection()
    if not conn:
        print("❌ Could not connect to DB.")
    else:
        print("✅ Connected to DB.")
        cursor = conn.cursor()
        
        # Check Tables
        cursor.execute("SHOW TABLES")
        tables = [x[0] for x in cursor.fetchall()]
        print(f"📊 Tables found: {tables}")
        
        if 'traffic_logs' in tables:
            # Get Count
            cursor.execute("SELECT COUNT(*) FROM traffic_logs")
            count = cursor.fetchone()[0]
            print(f"📈 Total Traffic Logs: {count}")
            
            # Get Recent Logs
            print("\n📝 Last 5 Log Entries:")
            cursor.execute("SELECT timestamp, src_ip, dst_ip, prediction FROM traffic_logs ORDER BY id DESC LIMIT 5")
            logs = cursor.fetchall()
            for log in logs:
                print(f"   - [{log[0]}] {log[1]} -> {log[2]} : {log[3]}")
            
        else:
            print("❌ Table 'traffic_logs' MISSING!")
            
        cursor.close()
        conn.close()
except Exception as e:
    print(f"⚠️ Exception: {e}")
