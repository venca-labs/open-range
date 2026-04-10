        CREATE DATABASE IF NOT EXISTS app;
        USE app;
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            password VARCHAR(128) NOT NULL,
            role VARCHAR(64) NOT NULL,
            department VARCHAR(64) NOT NULL,
            email VARCHAR(128) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            asset_id VARCHAR(64) NOT NULL,
            asset_class VARCHAR(64) NOT NULL,
            contents TEXT NOT NULL
        );
        INSERT INTO users (username, password, role, department, email) VALUES ('sales-01', 'sales-01-pass', 'sales', 'sales', 'sales-01@corp.local');
INSERT INTO users (username, password, role, department, email) VALUES ('sales-02', 'sales-02-pass', 'sales', 'sales', 'sales-02@corp.local');
INSERT INTO users (username, password, role, department, email) VALUES ('engineer-01', 'engineer-01-pass', 'engineer', 'engineer', 'engineer-01@corp.local');
INSERT INTO users (username, password, role, department, email) VALUES ('finance-01', 'finance-01-pass', 'finance', 'finance', 'finance-01@corp.local');
INSERT INTO users (username, password, role, department, email) VALUES ('it_admin-01', 'it_admin-01-pass', 'it_admin', 'it_admin', 'it_admin-01@corp.local');
        INSERT INTO assets (asset_id, asset_class, contents) VALUES ('payroll_db', 'crown_jewel', 'seeded-crown_jewel-payroll_db');
