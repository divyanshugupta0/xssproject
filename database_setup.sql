-- Create database
CREATE DATABASE IF NOT EXISTS xss_portal;
USE xss_portal;

-- Grant permissions to xss_user
GRANT ALL PRIVILEGES ON xss_portal.* TO 'xss_user'@'localhost';
FLUSH PRIVILEGES;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL unique,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(30) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create logs table
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_input TEXT,
    security_mode VARCHAR(20),
    vulnerability_detected VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users
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

GRANT ALL PRIVILEGES ON xss_portal.* TO 'xss_user'@'localhost';
FLUSH PRIVILEGES;

select * from users;