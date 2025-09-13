// Security Dashboard JavaScript - MySQL Backend
let activityData = [];
let terminalLines = [];
let isMonitoring = false;
let usersDatabase = [];

const sampleLogs = [
    { action: 'PAGE_LOAD', input: 'dashboard.html', mode: 'monitor', vulnerable: false },
    { action: 'API_CALL', input: '/api/users/list', mode: 'high', vulnerable: false },
    { action: 'USER_INPUT', input: '<script>alert("XSS")</script>', mode: 'low', vulnerable: true },
    { action: 'SQL_INJECTION', input: "'; DROP TABLE users; --", mode: 'low', vulnerable: true }
];

function log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = type === 'error' ? '❌' : type === 'warning' ? '⚠️' : '✅';
    const logLine = `[${timestamp}] ${prefix} ${message}`;
    terminalLines.push(logLine);
    if (terminalLines.length > 100) {
        terminalLines = terminalLines.slice(-100);
    }
    updateTerminal();
}

function updateTerminal() {
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = terminalLines.join('<br>');
    terminal.scrollTop = terminal.scrollHeight;
}

function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

function addActivityLog(action, input, mode, vulnerable = false) {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = {
        timestamp,
        action,
        input: sanitizeInput(input),
        mode,
        vulnerable
    };
    
    activityData.unshift(logEntry);
    if (activityData.length > 50) {
        activityData = activityData.slice(0, 50);
    }
    
    updateActivityLogs();
    updateStats();
    
    const status = vulnerable ? 'VULNERABLE' : 'SAFE';
    log(`${action}: ${input} [${status}]`, vulnerable ? 'warning' : 'info');
}

function updateActivityLogs() {
    const logsDiv = document.getElementById('activityLogs');
    
    if (activityData.length === 0) {
        logsDiv.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📭</div>
                <div>No activity logs yet</div>
                <div>Click "Add Sample" to see demo data</div>
            </div>
        `;
        return;
    }
    
    logsDiv.innerHTML = activityData.map(logEntry => `
        <div class="log-entry ${logEntry.vulnerable ? 'vulnerable' : ''}">
            <div class="log-time">${logEntry.timestamp} - ${logEntry.action} - Mode: ${logEntry.mode}</div>
            <div class="log-input">Input: "${logEntry.input}"</div>
            ${logEntry.vulnerable ? '<div class="vulnerability-alert">⚠️ VULNERABILITY DETECTED</div>' : ''}
        </div>
    `).join('');
}

function updateStats() {
    document.getElementById('searchCount').textContent = activityData.length;
    document.getElementById('vulnCount').textContent = activityData.filter(log => log.vulnerable).length;
}

function generateRandomActivity() {
    const actions = ['PAGE_LOAD', 'API_CALL', 'USER_INPUT', 'FILE_ACCESS', 'LOGIN_ATTEMPT'];
    const inputs = ['dashboard.html', '/api/data', 'search query', '/files/report.pdf', 'user@example.com'];
    const modes = ['low', 'medium', 'high'];
    
    const randomAction = actions[Math.floor(Math.random() * actions.length)];
    const randomInput = inputs[Math.floor(Math.random() * inputs.length)];
    const randomMode = modes[Math.floor(Math.random() * modes.length)];
    const isVulnerable = Math.random() < 0.2;
    
    addActivityLog(randomAction, randomInput, randomMode, isVulnerable);
}

// Event listeners
document.getElementById('refreshBtn').addEventListener('click', async function() {
    log('Refreshing dashboard data...');
    await loadActivityLogs();
    updateActivityLogs();
    updateStats();
    log('Dashboard refreshed successfully');
});

// Load activity logs from MySQL
async function loadActivityLogs() {
    try {
        const response = await fetch('/api/logs');
        const data = await response.json();
        
        if (data.logs) {
            activityData = data.logs.map(log => ({
                timestamp: new Date(log.timestamp).toLocaleTimeString(),
                action: log.action,
                input: sanitizeInput(log.user_input || ''),
                mode: log.security_mode,
                vulnerable: log.vulnerability_detected === 'XSS_DETECTED'
            }));
        }
    } catch (error) {
        log('Error loading activity logs: ' + error.message, 'error');
    }
}

document.getElementById('clearBtn').addEventListener('click', async function() {
    if (!confirm('Clear all activity logs?')) return;
    log('Clearing all activity logs...');
    
    try {
        const response = await fetch('/api/clear_logs', { method: 'POST' });
        const result = await response.json();
        
        if (result.success) {
            activityData = [];
            updateActivityLogs();
            updateStats();
            log('All logs cleared successfully');
        } else {
            log('Failed to clear logs', 'error');
        }
    } catch (error) {
        log('Error clearing logs: ' + error.message, 'error');
    }
});

document.getElementById('addSampleBtn').addEventListener('click', function() {
    log('Adding sample data...');
    sampleLogs.forEach((sample, i) => {
        setTimeout(() => {
            addActivityLog(sample.action, sample.input, sample.mode, sample.vulnerable);
        }, i * 500);
    });
    log('Sample data added');
});

document.getElementById('exportBtn').addEventListener('click', function() {
    log('Exporting activity data...');
    const csv = 'Timestamp,Action,Input,Mode,Vulnerable\n' +
        activityData.map(log => 
            `${log.timestamp},${log.action},"${log.input}",${log.mode},${log.vulnerable}`
        ).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_logs_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    log('Data exported successfully');
});

document.getElementById('clearTerminalBtn').addEventListener('click', function() {
    terminalLines = [];
    updateTerminal();
});

document.getElementById('testXSSBtn').addEventListener('click', function() {
    log('Testing XSS payload...', 'warning');
    addActivityLog('XSS_TEST', '<script>alert("XSS")</script>', 'low', true);
    log('XSS test completed - vulnerability detected', 'warning');
});

document.getElementById('attackBtn').addEventListener('click', function() {
    log('Simulating security attack...', 'warning');
    const attacks = [
        { input: '<script>alert("XSS")</script>', type: 'XSS' },
        { input: "'; DROP TABLE users; --", type: 'SQL_INJECTION' },
        { input: '<img src=x onerror=alert(1)>', type: 'XSS' },
        { input: "' OR '1'='1", type: 'SQL_INJECTION' }
    ];
    
    attacks.forEach((attack, i) => {
        setTimeout(() => {
            addActivityLog('ATTACK_SIMULATION', attack.input, 'low', true);
            log(`${attack.type} attack simulated`, 'warning');
        }, i * 1000);
    });
});

document.getElementById('monitorBtn').addEventListener('click', function() {
    const btn = document.getElementById('monitorBtn');
    if (!isMonitoring) {
        isMonitoring = true;
        btn.textContent = '⏸️ Stop Monitoring';
        btn.classList.add('pulse');
        log('Real-time monitoring started');
        
        const monitorInterval = setInterval(() => {
            if (!isMonitoring) {
                clearInterval(monitorInterval);
                return;
            }
            generateRandomActivity();
        }, Math.random() * 5000 + 3000);
        
        btn.monitorInterval = monitorInterval;
    } else {
        isMonitoring = false;
        btn.textContent = '📡 Start Monitoring';
        btn.classList.remove('pulse');
        if (btn.monitorInterval) {
            clearInterval(btn.monitorInterval);
        }
        log('Monitoring stopped');
    }
});

document.getElementById('reportBtn').addEventListener('click', function() {
    log('Generating security report...');
    const totalLogs = activityData.length;
    const vulnCount = activityData.filter(log => log.vulnerable).length;
    const safeCount = totalLogs - vulnCount;
    const riskLevel = vulnCount > 5 ? 'HIGH' : vulnCount > 2 ? 'MEDIUM' : 'LOW';
    
    const report = `Security Report Generated at ${new Date().toLocaleString()}\n\nTotal Activities: ${totalLogs}\nSafe Activities: ${safeCount}\nVulnerable Activities: ${vulnCount}\nRisk Level: ${riskLevel}`;
    
    alert(report);
    log('Security report generated');
});

document.getElementById('clearDbBtn').addEventListener('click', function() {
    if (!confirm('Clear entire database? This will remove all stored data.')) return;
    log('Clearing database...', 'warning');
    activityData = [];
    terminalLines = [];
    updateActivityLogs();
    updateStats();
    updateTerminal();
    log('Database cleared successfully');
});

document.getElementById('viewDbBtn').addEventListener('click', function() {
    log('Opening database viewer...');
    showDatabaseModal();
});

document.getElementById('addDataBtn').addEventListener('click', function() {
    log('Opening add data form...');
    showAddDataModal();
});

document.getElementById('addUserForm').addEventListener('submit', function(e) {
    e.preventDefault();
    addUserToDatabase();
});

document.getElementById('regainDbBtn').addEventListener('click', async function() {
    if (!confirm('Regain database? This will recreate all tables and sample data.')) return;
    log('Regaining database...', 'info');
    
    try {
        const response = await fetch('/api/regain_database', { method: 'POST' });
        const result = await response.json();
        
        if (result.success) {
            log('Database regained successfully', 'info');
            alert('Database regained successfully!');
        } else {
            log('Error regaining database: ' + result.error, 'error');
            alert('Error: ' + result.error);
        }
    } catch (error) {
        log('Error regaining database: ' + error.message, 'error');
        alert('Error: ' + error.message);
    }
});

async function showDatabaseModal() {
    const modal = document.getElementById('dbModal');
    const content = document.getElementById('dbContent');
    
    modal.style.display = 'block';
    content.innerHTML = 'Loading database contents...';
    
    try {
        // Load users from MySQL - try both empty query and wildcard
        let response = await fetch('/api/search?q=');
        let data = await response.json();
        
        // If no users found with empty query, try wildcard search
        if (!data.users || data.users.length === 0) {
            response = await fetch('/api/search?q=a');
            data = await response.json();
        }
        
        displayDatabaseContent(data.users || []);
    } catch (error) {
        log('Error loading database: ' + error.message, 'error');
        content.innerHTML = '<p style="color: red;">Error loading database contents</p>';
    }
}

function displayDatabaseContent(users) {
    const content = document.getElementById('dbContent');
    
    setTimeout(() => {
        const dbData = {
            users: users,
            logs: activityData.slice(0, 10)
        };
        
        let html = '<h3>Users Table</h3>';
        html += '<table class="db-table">';
        html += '<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>';
        
        dbData.users.forEach(user => {
            html += `<tr><td>${user.id}</td><td>${user.username}</td><td>${user.email}</td><td>${user.role}</td></tr>`;
        });
        
        html += '</table>';
        
        if (dbData.logs.length > 0) {
            html += '<h3 style="margin-top: 20px;">Recent Activity Logs</h3>';
            html += '<table class="db-table">';
            html += '<tr><th>Time</th><th>Action</th><th>Input</th><th>Vulnerable</th></tr>';
            
            dbData.logs.forEach(log => {
                html += `<tr><td>${log.timestamp}</td><td>${log.action}</td><td>${log.input}</td><td>${log.vulnerable ? 'Yes' : 'No'}</td></tr>`;
            });
            
            html += '</table>';
        }
        
        content.innerHTML = html;
    }, 500);
}

function closeDbModal() {
    document.getElementById('dbModal').style.display = 'none';
}

function showAddDataModal() {
    document.getElementById('addDataModal').style.display = 'block';
}

function closeAddDataModal() {
    document.getElementById('addDataModal').style.display = 'none';
    document.getElementById('addUserForm').reset();
}

async function addUserToDatabase() {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    
    log(`Adding user: ${username} (${email}) - ${role}`);
    
    try {
        const response = await fetch('/api/add_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                email: email,
                role: role
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            log('User added to MySQL successfully', 'info');
            addActivityLog('USER_ADDED', `${username}:${email}:${role}`, 'admin', false);
            closeAddDataModal();
            alert(`User "${username}" added to MySQL database successfully!`);
        } else {
            log('Error adding user: ' + result.error, 'error');
            alert('Error adding user: ' + result.error);
        }
        
    } catch (error) {
        log('Error adding user: ' + error.message, 'error');
        alert('Error adding user: ' + error.message);
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const dbModal = document.getElementById('dbModal');
    const addModal = document.getElementById('addDataModal');
    
    if (event.target === dbModal) {
        closeDbModal();
    }
    if (event.target === addModal) {
        closeAddDataModal();
    }
};

// Initialize dashboard
log('Security Dashboard initialized - MySQL Backend');
log('Ready for monitoring');

// Load initial data
loadActivityLogs().then(() => {
    updateActivityLogs();
    updateStats();
});