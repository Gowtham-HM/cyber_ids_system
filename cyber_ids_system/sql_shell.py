import database
import mysql.connector

def run_shell():
    print("="*60)
    print("💻 CYBER IDS SQL SHELL")
    print("="*60)
    print("Type your SQL query and press Enter.")
    print("Type 'tables' to list tables.")
    print("Type 'exit' to quit.")
    print("-" * 60)

    conn = database.get_connection()
    if not conn:
        print("❌ Could not connect to database.")
        return

    cursor = conn.cursor()

    while True:
        try:
            query = input("\nsql> ").strip()
            
            if query.lower() in ['exit', 'quit']:
                break
            
            if not query:
                continue

            if query.lower() == 'tables':
                query = "SHOW TABLES"

            # Execute
            cursor.execute(query)
            
            # Check if it's a SELECT query (returns data)
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
                results = cursor.fetchall()
                
                print(f"\n✅ Found {len(results)} rows:")
                print(" | ".join(columns))
                print("-" * (len(columns) * 15))
                
                for row in results:
                    print(" | ".join(str(r) for r in row))
            else:
                conn.commit()
                print(f"✅ Query executed successfully. Rows affected: {cursor.rowcount}")

        except mysql.connector.Error as err:
            print(f"❌ SQL Error: {err}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")

    print("\n👋 Exiting shell.")
    cursor.close()
    conn.close()

if __name__ == "__main__":
    run_shell()
