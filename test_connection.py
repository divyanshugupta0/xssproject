import mysql.connector

# Test MySQL connection
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'xss_user',
    'password': 'password123',
    'database': 'xss_portal'
}

try:
    db = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    result = cursor.fetchone()
    print(f"✅ Connection successful! Found {result[0]} users in database.")
    cursor.close()
    db.close()
except Exception as e:
    print(f"❌ Connection failed: {e}")
    print("\nCheck:")
    print("1. MySQL server is running")
    print("2. Username/password are correct")
    print("3. Database 'xss_portal' exists")