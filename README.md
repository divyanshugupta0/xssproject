# XSS Vulnerability Portal

A deliberately vulnerable web application for demonstrating XSS (Cross-Site Scripting) attacks.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open browser and go to: `http://localhost:5000`

## Vulnerabilities

### XSS Reflected Vulnerability
The search functionality is vulnerable to reflected XSS attacks. User input is directly inserted into the HTML without proper escaping.

### Test Payloads
Try these in the search box:
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`

## Database
Uses SQLite database with sample user data for search functionality.

## Warning
This application contains intentional security vulnerabilities. Use only for educational purposes in a controlled environment.