-- OpenRange base database initialization
-- The Builder overlays additional schemas, users, and vuln-specific data per episode.

CREATE DATABASE IF NOT EXISTS referral_db;
USE referral_db;

-- Users table (portal authentication)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(128),
    role VARCHAR(32) DEFAULT 'user',
    department VARCHAR(64),
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Patient referrals (core business data / PHI)
CREATE TABLE IF NOT EXISTS patient_referrals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_name VARCHAR(128) NOT NULL,
    dob DATE,
    diagnosis TEXT,
    referring_physician VARCHAR(128),
    specialist VARCHAR(128),
    insurance_policy VARCHAR(64),
    status ENUM('pending', 'approved', 'completed', 'denied') DEFAULT 'pending',
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Patients table (contact information)
CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(64) NOT NULL,
    last_name VARCHAR(64) NOT NULL,
    dob DATE,
    address VARCHAR(256),
    phone VARCHAR(20),
    email VARCHAR(128),
    emergency_contact VARCHAR(128),
    insurance_id VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Billing records
CREATE TABLE IF NOT EXISTS billing (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    claim_number VARCHAR(64),
    amount DECIMAL(10, 2),
    status ENUM('submitted', 'approved', 'denied', 'paid') DEFAULT 'submitted',
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

-- Sessions table (active user sessions)
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(128),
    active TINYINT DEFAULT 1,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Access log table (application-level audit trail)
CREATE TABLE IF NOT EXISTS access_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    page VARCHAR(256),
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Flags database (capture-the-flag values planted by Builder)
CREATE DATABASE IF NOT EXISTS flags;
USE flags;

CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(64) NOT NULL,
    flag VARCHAR(128) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Grant privileges to app user
USE referral_db;
GRANT SELECT, INSERT, UPDATE ON referral_db.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
