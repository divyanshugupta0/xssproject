# MySQL Remote Connection Setup

## Local MySQL Setup

1. **Configure MySQL for remote connections**:
   ```sql
   -- Connect to MySQL as root
   mysql -u root -p
   
   -- Create database and user
   CREATE DATABASE xss_portal;
   CREATE USER 'xss_user'@'%' IDENTIFIED BY 'password123';
   GRANT ALL PRIVILEGES ON xss_portal.* TO 'xss_user'@'%';
   FLUSH PRIVILEGES;
   ```

2. **Edit MySQL configuration** (`my.cnf` or `my.ini`):
   ```ini
   [mysqld]
   bind-address = 0.0.0.0
   port = 3306
   ```

3. **Restart MySQL service**:
   ```bash
   # Linux/Mac
   sudo systemctl restart mysql
   
   # Windows
   net stop mysql
   net start mysql
   ```

4. **Configure firewall**:
   ```bash
   # Linux
   sudo ufw allow 3306
   
   # Windows
   netsh advfirewall firewall add rule name="MySQL" dir=in action=allow protocol=TCP localport=3306
   ```

## Router Configuration

1. **Port forwarding**: Forward port 3306 to your local machine
2. **Get public IP**: Visit https://whatismyipaddress.com/

## Render Environment Variables

Set these on Render:

```
MYSQL_HOST=YOUR_PUBLIC_IP
MYSQL_USER=xss_user
MYSQL_PASSWORD=password123
MYSQL_DATABASE=xss_portal
MYSQL_PORT=3306
```

## Database Setup Script

Run this on your local MySQL:

```sql
USE xss_portal;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(30) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_input TEXT,
    security_mode VARCHAR(20),
    vulnerability_detected VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, email, role) VALUES 
    ('admin', 'admin@portal.com', 'administrator'),
    ('john_doe', 'john@example.com', 'user'),
    ('jane_smith', 'jane@example.com', 'moderator'),
    ('test_user', 'test@portal.com', 'user'),
    ('guest', 'guest@portal.com', 'guest'),
    ('alice_cooper', 'alice@security.com', 'security_analyst'),
    ('bob_wilson', 'bob@dev.com', 'developer'),
    ('charlie_brown', 'charlie@qa.com', 'tester'),
    ('divyanshu019','divyanshu019@gmail.com', 'superadmin'),
    ('radharani','radhakrishna@gmail.com', 'worldadmin');
```

## Security Notes

⚠️ **Warning**: Exposing MySQL to internet has risks:
- Use strong passwords
- Consider VPN instead
- Restrict IP access if possible
- Use SSL/TLS encryption

## Testing Connection

Test locally:
```python
import mysql.connector
conn = mysql.connector.connect(
    host='YOUR_PUBLIC_IP',
    user='xss_user',
    password='password123',
    database='xss_portal',
    port=3306
)
print("Connection successful!")
```