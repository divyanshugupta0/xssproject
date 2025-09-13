from flask import Flask, request, render_template_string, g, jsonify, session
import mysql.connector
import os
import html
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'vulnerable_key_for_demo'

# MySQL Database configuration
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_USER = os.getenv('MYSQL_USER', 'xss_user')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password123')
MYSQL_DATABASE = os.getenv('MYSQL_DATABASE', 'xss_portal')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', '3306'))

MYSQL_CONFIG = {
    'host': MYSQL_HOST,
    'user': MYSQL_USER,
    'password': MYSQL_PASSWORD,
    'database': MYSQL_DATABASE,
    'port': MYSQL_PORT
}

# Security modes
SECURITY_MODES = {
    'high': {'name': 'High Security', 'color': '#28a745', 'xss_protection': True, 'sql_protection': True},
    'moderate': {'name': 'Moderate Security', 'color': '#ffc107', 'xss_protection': True, 'sql_protection': False},
    'low': {'name': 'Low Security (Vulnerable)', 'color': '#dc3545', 'xss_protection': False, 'sql_protection': False}
}

def get_db():
    try:
        return mysql.connector.connect(**MYSQL_CONFIG)
    except mysql.connector.Error:
        # Fallback to SQLite if MySQL connection fails
        import sqlite3
        return sqlite3.connect('xss_portal.db')

def log_activity(action, user_input, security_mode, vulnerability_detected=''):
    try:
        db = get_db()
        cursor = db.cursor()
        if isinstance(db, mysql.connector.MySQLConnection):
            cursor.execute(
                "INSERT INTO logs (timestamp, action, user_input, security_mode, vulnerability_detected) VALUES (%s, %s, %s, %s, %s)",
                (datetime.now(), action, user_input, security_mode, vulnerability_detected)
            )
        else:
            cursor.execute(
                "INSERT INTO logs (timestamp, action, user_input, security_mode, vulnerability_detected) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(), action, user_input, security_mode, vulnerability_detected)
            )
        db.commit()
        cursor.close()
        db.close()
    except:
        pass

def detect_xss(input_text):
    xss_patterns = ['<script', '<img', '<svg', '<iframe', 'javascript:', 'onerror', 'onload', 'onclick']
    return any(pattern.lower() in input_text.lower() for pattern in xss_patterns)

def sanitize_input(input_text, mode):
    if mode == 'high':
        return html.escape(input_text)
    elif mode == 'moderate':
        return html.escape(input_text)
    else:
        return input_text  # Vulnerable mode

@app.route('/api/set_mode', methods=['POST'])
def set_security_mode():
    mode = request.json.get('mode', 'low')
    if mode in SECURITY_MODES:
        session['security_mode'] = mode
        return jsonify({'success': True, 'mode': mode})
    return jsonify({'success': False})

@app.route('/api/search')
def api_search():
    search_query = request.args.get('q', '')
    security_mode = session.get('security_mode', 'low')
    
    # Log the search activity
    vulnerability_detected = ''
    if detect_xss(search_query):
        vulnerability_detected = 'XSS_DETECTED'
    
    log_activity('SEARCH', search_query, security_mode, vulnerability_detected)
    
    db = get_db()
    cursor = db.cursor()
    
    if search_query:
        # SQL Injection protection based on security mode
        if SECURITY_MODES[security_mode]['sql_protection']:
            if isinstance(db, mysql.connector.MySQLConnection):
                cursor.execute(
                    "SELECT * FROM users WHERE username LIKE %s OR email LIKE %s OR role LIKE %s", 
                    (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
                )
            else:
                cursor.execute(
                    "SELECT * FROM users WHERE username LIKE ? OR email LIKE ? OR role LIKE ?", 
                    (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
                )
        else:
            # Vulnerable SQL query for demonstration
            try:
                query = f"SELECT * FROM users WHERE username LIKE '%{search_query}%' OR email LIKE '%{search_query}%' OR role LIKE '%{search_query}%'"
                cursor.execute(query)
            except:
                if isinstance(db, mysql.connector.MySQLConnection):
                    cursor.execute(
                        "SELECT * FROM users WHERE username LIKE %s OR email LIKE %s OR role LIKE %s", 
                        (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM users WHERE username LIKE ? OR email LIKE ? OR role LIKE ?", 
                        (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
                    )
    else:
        # Return all users when no search query
        cursor.execute("SELECT * FROM users")
    
    results = cursor.fetchall()
    
    users = []
    for row in results:
        users.append({
            'id': row[0],
            'username': row[1], 
            'email': row[2],
            'role': row[3]
        })
    
    cursor.close()
    db.close()
    
    # Apply XSS protection based on security mode
    safe_search_term = sanitize_input(search_query, security_mode)
    
    return jsonify({
        'users': users, 
        'search_term': safe_search_term if SECURITY_MODES[security_mode]['xss_protection'] else search_query,
        'security_mode': security_mode,
        'vulnerability_detected': vulnerability_detected
    })

@app.route('/api/logs')
def get_logs():
    if session.get('security_mode') == 'high':
        return jsonify({'error': 'Access denied in high security mode'}), 403
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20")
        logs = cursor.fetchall()
        
        log_data = []
        for row in logs:
            log_data.append({
                'id': row[0],
                'timestamp': row[1].isoformat() if row[1] else '',
                'action': row[2],
                'user_input': row[3],
                'security_mode': row[4],
                'vulnerability_detected': row[5]
            })
        
        cursor.close()
        db.close()
        return jsonify({'logs': log_data})
    except:
        return jsonify({'logs': []})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    if session.get('security_mode') == 'high':
        return jsonify({'error': 'Access denied in high security mode'}), 403
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM logs")
        db.commit()
        cursor.close()
        db.close()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False})

@app.route('/files/<filename>')
def serve_file(filename):
    return f"Demo file: {filename}", 200, {'Content-Type': 'text/plain'}

@app.route('/api/data')
def api_data():
    if session.get('security_mode') == 'high':
        return jsonify({'error': 'Access denied in high security mode'}), 403
    return api_search()

@app.route('/api/regain_database', methods=['POST'])
def regain_database():
    try:
        db = get_db()
        cursor = db.cursor()
        
        if isinstance(db, mysql.connector.MySQLConnection):
            sql_commands = [
                """CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    email VARCHAR(100) NOT NULL,
                    role VARCHAR(30) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""",
                """CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    user_input TEXT,
                    security_mode VARCHAR(20),
                    vulnerability_detected VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""",
                """INSERT IGNORE INTO users (username, email, role) VALUES 
                    ('admin', 'admin@portal.com', 'administrator'),
                    ('john_doe', 'john@example.com', 'user'),
                    ('jane_smith', 'jane@example.com', 'moderator'),
                    ('test_user', 'test@portal.com', 'user'),
                    ('guest', 'guest@portal.com', 'guest'),
                    ('alice_cooper', 'alice@security.com', 'security_analyst'),
                    ('bob_wilson', 'bob@dev.com', 'developer'),
                    ('charlie_brown', 'charlie@qa.com', 'tester'),
                    ('divyanshu019','divyanshu019@gmail.com', 'superadmin'),
                    ('radharani','radhakrishna@gmail.com', 'worldadmin')"""
            ]
        else:
            sql_commands = [
                """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""",
                """CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    action TEXT NOT NULL,
                    user_input TEXT,
                    security_mode TEXT,
                    vulnerability_detected TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )"""
            ]
            
            sample_users = [
                ('admin', 'admin@portal.com', 'administrator'),
                ('john_doe', 'john@example.com', 'user'),
                ('jane_smith', 'jane@example.com', 'moderator'),
                ('test_user', 'test@portal.com', 'user'),
                ('guest', 'guest@portal.com', 'guest'),
                ('alice_cooper', 'alice@security.com', 'security_analyst'),
                ('bob_wilson', 'bob@dev.com', 'developer'),
                ('charlie_brown', 'charlie@qa.com', 'tester'),
                ('divyanshu019','divyanshu019@gmail.com', 'superadmin'),
                ('radharani','radhakrishna@gmail.com', 'worldadmin')
            ]
        
        for command in sql_commands:
            cursor.execute(command)
            
        if not isinstance(db, mysql.connector.MySQLConnection):
            for user in sample_users:
                try:
                    cursor.execute('INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)', user)
                except:
                    pass
            
        db.commit()
        cursor.close()
        db.close()
        
        return jsonify({'success': True, 'message': 'Database regained successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/users/list')
def list_users():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        user_list = []
        for row in users:
            user_list.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3]
            })
        
        cursor.close()
        db.close()
        return jsonify({'users': user_list})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/add_user', methods=['POST'])
def add_user():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        role = data.get('role')
        
        if not username or not email or not role:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        db = get_db()
        cursor = db.cursor()
        if isinstance(db, mysql.connector.MySQLConnection):
            cursor.execute(
                "INSERT INTO users (username, email, role) VALUES (%s, %s, %s)", 
                (username, email, role)
            )
        else:
            cursor.execute(
                "INSERT INTO users (username, email, role) VALUES (?, ?, ?)", 
                (username, email, role)
            )
        db.commit()
        user_id = cursor.lastrowid
        cursor.close()
        db.close()
        
        log_activity('USER_ADDED', f'{username}:{email}:{role}', 'admin', '')
        
        return jsonify({'success': True, 'user_id': user_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/settings')
def settings():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Settings - Security Portal</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
            .card { background: white; border-radius: 15px; padding: 30px; margin: 20px 0; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
            .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; margin: 10px 5px; font-weight: 600; }
            .btn-primary { background: #007bff; color: white; }
            .btn-danger { background: #dc3545; color: white; }
            .btn-success { background: #28a745; color: white; }
            h1 { color: white; text-align: center; margin-bottom: 30px; }
            .setting-item { padding: 15px; margin: 10px 0; border: 1px solid #e9ecef; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Portal Settings</h1>
            
            <div class="card">
                <h3>Database Management</h3>
                <div class="setting-item">
                    <h4>Clear Activity Logs</h4>
                    <p>Remove all stored activity logs from the database</p>
                    <button class="btn btn-danger" onclick="clearAllLogs()">Clear All Logs</button>
                </div>
                
                <div class="setting-item">
                    <h4>Reset Database</h4>
                    <p>Reset the entire database to initial state</p>
                    <button class="btn btn-danger" onclick="resetDatabase()">Reset Database</button>
                </div>
            </div>
            
            <div class="card">
                <h3>Security Configuration</h3>
                <div class="setting-item">
                    <h4>Default Security Mode</h4>
                    <p>Set the default security mode for new sessions</p>
                    <select id="defaultMode" class="btn">
                        <option value="low">Low Security (Vulnerable)</option>
                        <option value="moderate">Moderate Security</option>
                        <option value="high">High Security</option>
                    </select>
                    <button class="btn btn-success" onclick="saveDefaultMode()">Save</button>
                </div>
            </div>
            
            <div class="card">
                <h3>Navigation</h3>
                <button class="btn btn-primary" onclick="window.location.href='/'">← Back to Portal</button>
                <button class="btn btn-primary" onclick="window.location.href='/dashboard'">📊 Dashboard</button>
            </div>
        </div>
        
        <script>
            async function clearAllLogs() {
                if (confirm('Are you sure you want to clear all logs?')) {
                    const response = await fetch('/api/clear_logs', { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        alert('All logs cleared successfully!');
                    } else {
                        alert('Failed to clear logs');
                    }
                }
            }
            
            function resetDatabase() {
                alert('Database reset functionality - Demo only');
            }
            
            function saveDefaultMode() {
                const mode = document.getElementById('defaultMode').value;
                alert(`Default mode set to: ${mode} (Demo only)`);
            }
        </script>
    </body>
    </html>
    ''')

@app.route('/dashboard.html')
def dashboard_html():
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Dashboard file not found", 404

@app.route('/dashboard.js')
def dashboard_js():
    try:
        with open('dashboard.js', 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'application/javascript'}
    except FileNotFoundError:
        return "Dashboard JS file not found", 404

@app.route('/dashboard')
def dashboard():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Dashboard</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .dashboard { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .card { background: white; border-radius: 12px; padding: 20px; margin: 15px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .header { text-align: center; color: white; margin-bottom: 30px; }
            .logs-container { max-height: 400px; overflow-y: auto; }
            .log-entry { padding: 8px; margin: 5px 0; border-radius: 6px; font-size: 12px; }
            .log-entry.vulnerable { background: #f8d7da; border-left: 4px solid #dc3545; }
            .log-entry.safe { background: #d4edda; border-left: 4px solid #28a745; }
            .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; margin: 5px; }
            .btn-primary { background: #007bff; color: white; }
        </style>
    </head>
    <body>
        <div class="dashboard">
            <div class="header">
                <h1>🛡️ Security Monitoring Dashboard</h1>
                <p>Real-time vulnerability detection and logging</p>
            </div>
            
            <div class="card">
                <h3>🔍 Activity Logs</h3>
                <button class="btn btn-primary" onclick="loadLogs()">Refresh Logs</button>
                <div id="logs" class="logs-container"></div>
            </div>
            
            <div class="card">
                <h3>🎯 Quick Actions</h3>
                <button class="btn btn-primary" onclick="window.open('/', '_blank')">Open Main Portal</button>
                <button class="btn btn-primary" onclick="clearLogs()">Clear Logs</button>
                <button class="btn btn-primary" onclick="exportLogs()">Export Logs</button>
            </div>
        </div>
        
        <script>
            async function loadLogs() {
                try {
                    const response = await fetch('/api/logs');
                    const data = await response.json();
                    
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = '';
                    
                    if (data.logs.length === 0) {
                        logsDiv.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No activity logs yet. Start searching to see logs.</div>';
                        return;
                    }
                    
                    data.logs.forEach(log => {
                        const logDiv = document.createElement('div');
                        logDiv.className = `log-entry ${log.vulnerability_detected ? 'vulnerable' : 'safe'}`;
                        logDiv.innerHTML = `
                            <strong>${log.timestamp}</strong> - ${log.action} - Mode: ${log.security_mode}
                            <br>Input: "${log.user_input}"
                            ${log.vulnerability_detected ? '<br><span style="color: red;">⚠️ ' + log.vulnerability_detected + '</span>' : ''}
                        `;
                        logsDiv.appendChild(logDiv);
                    });
                } catch (error) {
                    document.getElementById('logs').innerHTML = '<div style="padding: 20px; text-align: center; color: #dc3545;">Error loading logs</div>';
                }
            }
            
            async function clearLogs() {
                if (confirm('Clear all activity logs?')) {
                    const response = await fetch('/api/clear_logs', { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        loadLogs();
                        alert('Logs cleared successfully!');
                    }
                }
            }
            
            function exportLogs() {
                fetch('/api/logs')
                    .then(response => response.json())
                    .then(data => {
                        const logs = data.logs.map(log => 
                            `${log.timestamp},${log.action},"${log.user_input}",${log.security_mode},${log.vulnerability_detected}`
                        ).join('\\n');
                        
                        const blob = new Blob(['Timestamp,Action,Input,Mode,Vulnerability\\n' + logs], { type: 'text/csv' });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'security_logs.csv';
                        a.click();
                    });
            }
            
            loadLogs();
            setInterval(loadLogs, 5000);
        </script>
    </body>
    </html>
    ''')

# Enhanced main page
@app.route('/')
def index():
    search_query = request.args.get('search', '')
    security_mode = session.get('security_mode', 'low')
    mode_info = SECURITY_MODES[security_mode]
    
    # Intentionally vulnerable: Direct insertion without escaping
    if search_query:
        # SQL query (also potentially vulnerable to SQL injection)
        db = get_db()
        cursor = db.cursor()
        
        # SQL Injection vulnerability based on security mode
        if SECURITY_MODES[security_mode]['sql_protection']:
            if isinstance(db, mysql.connector.MySQLConnection):
                cursor.execute("SELECT * FROM users WHERE username LIKE %s", (f'%{search_query}%',))
            else:
                cursor.execute("SELECT * FROM users WHERE username LIKE ?", (f'%{search_query}%',))
        else:
            # Vulnerable SQL query for demonstration
            try:
                query = f"SELECT * FROM users WHERE username LIKE '%{search_query}%'"
                cursor.execute(query)
            except:
                if isinstance(db, mysql.connector.MySQLConnection):
                    cursor.execute("SELECT * FROM users WHERE username LIKE %s", (f'%{search_query}%',))
                else:
                    cursor.execute("SELECT * FROM users WHERE username LIKE ?", (f'%{search_query}%',))
        
        results = cursor.fetchall()
        
        result_html = ""
        for row in results:
            result_html += f"<div class='result'>ID: {row[0]}, User: {row[1]}, Email: {row[2]}, Role: {row[3]}</div>"
        
        if not results:
            result_html = "<div class='no-results'>No users found</div>"
        
        cursor.close()
        db.close()
    else:
        result_html = "<div class='info'>Enter a search term to find users</div>"
    
    # Apply security based on mode
    if mode_info['xss_protection']:
        safe_search_query = html.escape(search_query)
    else:
        safe_search_query = search_query
    
    # VULNERABLE or PROTECTED based on security mode
    template = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔐 Advanced Security Portal</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }}
            .navbar {{
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 15px 0;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
                position: sticky;
                top: 0;
                z-index: 1000;
            }}
            .nav-container {{
                max-width: 1200px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0 20px;
            }}
            .logo {{ font-size: 24px; font-weight: bold; color: #667eea; }}
            .nav-links {{ display: flex; gap: 20px; }}
            .nav-links a {{ text-decoration: none; color: #333; font-weight: 500; }}
            .container {{ 
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 40px 20px;
                display: grid;
                grid-template-columns: 1fr 300px;
                gap: 30px;
            }}
            .main-content {{
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            }}
            .sidebar {{
                display: flex;
                flex-direction: column;
                gap: 20px;
            }}
            .security-panel, .stats-panel {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }}
            .security-mode {{
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 15px;
                border-radius: 10px;
                margin: 10px 0;
                cursor: pointer;
                transition: all 0.3s ease;
                border: 2px solid transparent;
            }}
            .security-mode:hover {{ transform: translateY(-2px); }}
            .security-mode.active {{ border-color: #667eea; box-shadow: 0 5px 15px rgba(102,126,234,0.3); }}
            .mode-indicator {{ width: 20px; height: 20px; border-radius: 50%; }}
            .search-container {{
                background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                border-radius: 15px;
                padding: 30px;
                margin: 30px 0;
            }}
            .search-box {{
                display: flex;
                gap: 15px;
                margin-bottom: 20px;
            }}
            .search-input {{
                flex: 1;
                padding: 15px 20px;
                border: 2px solid #e9ecef;
                border-radius: 10px;
                font-size: 16px;
                transition: all 0.3s ease;
            }}
            .search-input:focus {{
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
            }}
            .search-btn {{
                padding: 15px 30px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 10px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
            }}
            .search-btn:hover {{ transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102,126,234,0.4); }}
            .results-section {{
                margin-top: 30px;
            }}
            .result-card {{
                background: #f8f9fa;
                border-radius: 12px;
                padding: 20px;
                margin: 15px 0;
                border-left: 5px solid #667eea;
                transition: all 0.3s ease;
            }}
            .result-card:hover {{ transform: translateX(5px); }}
            .no-results {{
                text-align: center;
                padding: 40px;
                color: #6c757d;
                font-style: italic;
            }}
            .payload-section {{
                background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
                border-radius: 15px;
                padding: 25px;
                margin-top: 30px;
            }}
            .payload-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }}
            .payload-item {{
                background: rgba(255,255,255,0.7);
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            .payload-item:hover {{
                background: rgba(255,255,255,0.9);
                transform: scale(1.02);
            }}
            .status-indicator {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 8px 15px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
            }}
            .vulnerability-alert {{
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
                border-radius: 10px;
                padding: 15px;
                margin: 15px 0;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            @media (max-width: 768px) {{
                .container {{ grid-template-columns: 1fr; }}
                .search-box {{ flex-direction: column; }}
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i> SecurePortal
                </div>
                <div class="nav-links">
                    <a href="/dashboard.html"><i class="fas fa-chart-line"></i> Dashboard</a>
                    <a href="/settings"><i class="fas fa-cog"></i> Settings</a>
                    <button onclick="regainDatabase()" style="background: #28a745; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer;"><i class="fas fa-database"></i> Regain DB</button>
                </div>
            </div>
        </nav>

        <div class="container">
            <main class="main-content">
                <h1><i class="fas fa-search"></i> Advanced User Search Portal</h1>
                <p style="color: #6c757d; margin-bottom: 30px;">Demonstrating different security levels and vulnerability detection</p>
                
                <div class="search-container">
                    <form method="GET" class="search-box">
                        <input type="text" name="search" value="{search_query}" placeholder="Search users by name, email, or role..." class="search-input">
                        <button type="submit" class="search-btn">
                            <i class="fas fa-search"></i> Search
                        </button>
                    </form>
                    
                    <div class="status-indicator" style="background: {mode_info['color']}20; color: {mode_info['color']}; border: 1px solid {mode_info['color']}40;">
                        <i class="fas fa-shield-alt"></i>
                        Current Mode: {mode_info['name']}
                    </div>
                </div>
                
                <div class="results-section">
                    <h3><i class="fas fa-list"></i> Search Results for: <span style="color: #667eea;">{safe_search_query}</span></h3>
                    {result_html}
                </div>
                
                <div class="payload-section">
                    <h4><i class="fas fa-bug"></i> XSS Testing Payloads</h4>
                    <p>Click any payload to copy to clipboard:</p>
                    <div class="payload-grid">
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'&lt;script&gt;alert("XSS Basic")&lt;/script&gt;' if security_mode == 'low' else '&lt;script&gt;alert("XSS Basic")&lt;/script&gt; [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'&lt;img src=x onerror=alert("XSS Image")&gt;' if security_mode == 'low' else '&lt;img src=x onerror=alert("XSS Image")&gt; [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'&lt;svg onload=alert("XSS SVG")&gt;' if security_mode == 'low' else '&lt;svg onload=alert("XSS SVG")&gt; [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'&lt;iframe src="javascript:alert(\'XSS iframe\')"&gt;' if security_mode == 'low' else '&lt;iframe src="javascript:alert(\'XSS iframe\')"&gt; [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'javascript:alert("XSS JavaScript")' if security_mode == 'low' else 'javascript:alert("XSS JavaScript") [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode == 'low' else 'showBlocked(this)'}">{'&lt;body onload=alert("XSS Body")&gt;' if security_mode == 'low' else '&lt;body onload=alert("XSS Body")&gt; [BLOCKED]'}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode in ['low', 'moderate'] else 'showBlocked(this)'}">{"; DROP TABLE users; --" if security_mode in ['low', 'moderate'] else "; DROP TABLE users; -- [BLOCKED]"}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode in ['low', 'moderate'] else 'showBlocked(this)'}">{ "OR 1=1" if security_mode in ['low', 'moderate'] else "OR 1=1 [BLOCKED]"}</div>
                        <div class="payload-item" onclick="{'copyToClipboard(this)' if security_mode in ['low', 'moderate'] else 'showBlocked(this)'}">{ "UNION SELECT * FROM users --" if security_mode in ['low', 'moderate'] else "UNION SELECT * FROM users -- [BLOCKED]"}</div>
                    </div>
                </div>
            </main>
            
            <aside class="sidebar">
                <div class="security-panel">
                    <h3><i class="fas fa-shield-alt"></i> Security Modes</h3>
                    <div class="security-mode" data-mode="high">
                        <div class="mode-indicator" style="background: #28a745;"></div>
                        <div>
                            <strong>High Security</strong>
                            <br><small>Full XSS & SQL protection</small>
                        </div>
                    </div>
                    <div class="security-mode" data-mode="moderate">
                        <div class="mode-indicator" style="background: #ffc107;"></div>
                        <div>
                            <strong>Moderate Security</strong>
                            <br><small>XSS protection only</small>
                        </div>
                    </div>
                    <div class="security-mode active" data-mode="low">
                        <div class="mode-indicator" style="background: #dc3545;"></div>
                        <div>
                            <strong>Vulnerable Mode</strong>
                            <br><small>No protection (Demo)</small>
                        </div>
                    </div>
                </div>
                
                <div class="stats-panel">
                    <h3><i class="fas fa-chart-bar"></i> Live Stats</h3>
                    <div id="stats">
                        <p><i class="fas fa-search"></i> Searches: <span id="searchCount">0</span></p>
                        <p><i class="fas fa-exclamation-triangle"></i> Vulnerabilities: <span id="vulnCount">0</span></p>
                        <p><i class="fas fa-clock"></i> Last Activity: <span id="lastActivity">None</span></p>
                    </div>
                </div>
            </aside>
        </div>
        
        <script>
            // Security mode switching
            document.querySelectorAll('.security-mode').forEach(mode => {{
                mode.addEventListener('click', async () => {{
                    const modeType = mode.dataset.mode;
                    
                    const response = await fetch('/api/set_mode', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{mode: modeType}})
                    }});
                    
                    if (response.ok) {{
                        document.querySelectorAll('.security-mode').forEach(m => m.classList.remove('active'));
                        mode.classList.add('active');
                        location.reload();
                    }}
                }});
            }});
            
            // Copy payload to clipboard
            function copyToClipboard(element) {{
                const text = element.textContent.replace(' [BLOCKED]', '');
                navigator.clipboard.writeText(text);
                element.style.background = 'rgba(40, 167, 69, 0.2)';
                setTimeout(() => {{
                    element.style.background = 'rgba(255,255,255,0.7)';
                }}, 1000);
            }}
            
            function showBlocked(element) {{
                element.style.background = 'rgba(220, 53, 69, 0.2)';
                alert('This payload is blocked in current security mode');
                setTimeout(() => {{
                    element.style.background = 'rgba(255,255,255,0.7)';
                }}, 1000);
            }}
            
            // Update stats
            async function updateStats() {{
                try {{
                    const response = await fetch('/api/logs');
                    const data = await response.json();
                    
                    const searchCount = document.getElementById('searchCount');
                    const vulnCount = document.getElementById('vulnCount');
                    const lastActivity = document.getElementById('lastActivity');
                    
                    if (searchCount) searchCount.textContent = data.logs.length;
                    if (vulnCount) vulnCount.textContent = data.logs.filter(log => log.vulnerability_detected).length;
                    
                    if (data.logs.length > 0 && lastActivity) {{
                        const lastLog = data.logs[0];
                        lastActivity.textContent = new Date(lastLog.timestamp).toLocaleTimeString();
                    }}
                }} catch (error) {{
                    console.error('Failed to update stats:', error);
                }}
            }}
            
            updateStats();
            setInterval(updateStats, 5000);
            
            // Set active security mode on page load
            const currentMode = '{security_mode}';
            document.querySelectorAll('.security-mode').forEach(mode => {{
                mode.classList.remove('active');
                if (mode.dataset.mode === currentMode) {{
                    mode.classList.add('active');
                }}
            }});
            
            // Regain database function
            async function regainDatabase() {{
                if (!confirm('Regain database? This will recreate all tables and sample data.')) return;
                try {{
                    const response = await fetch('/api/regain_database', {{ method: 'POST' }});
                    const result = await response.json();
                    if (result.success) {{
                        alert('Database regained successfully!');
                    }} else {{
                        alert('Error: ' + result.error);
                    }}
                }} catch (error) {{
                    alert('Error: ' + error.message);
                }}
            }}
        </script>
    </body>
    </html>
    '''
    
    return template

def init_sqlite_fallback():
    import sqlite3
    db = sqlite3.connect('xss_portal.db')
    cursor = db.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            action TEXT NOT NULL,
            user_input TEXT,
            security_mode TEXT,
            vulnerability_detected TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    sample_users = [
        ('admin', 'admin@portal.com', 'administrator'),
        ('john_doe', 'john@example.com', 'user'),
        ('jane_smith', 'jane@example.com', 'moderator'),
        ('test_user', 'test@portal.com', 'user'),
        ('guest', 'guest@portal.com', 'guest'),
        ('alice_cooper', 'alice@security.com', 'security_analyst'),
        ('bob_wilson', 'bob@dev.com', 'developer'),
        ('charlie_brown', 'charlie@qa.com', 'tester'),
        ('divyanshu019','divyanshu019@gmail.com', 'superadmin'),
        ('radharani','radhakrishna@gmail.com', 'worldadmin')
    ]
    
    for user in sample_users:
        try:
            cursor.execute('INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)', user)
        except:
            pass
            
    db.commit()
    cursor.close()
    db.close()

if __name__ == '__main__':
    try:
        print(f"Trying to connect to MySQL at {MYSQL_HOST}:{MYSQL_PORT}")
        mysql.connector.connect(**MYSQL_CONFIG)
        print("MySQL connection successful")
    except:
        print("MySQL connection failed, using SQLite fallback")
        init_sqlite_fallback()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)