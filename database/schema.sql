CREATE DATABASE installers_db;
USE installers_db;

CREATE TABLE installer (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    city VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL  -- Add this line
);

-- Update your INSERT statement to include passwords
INSERT INTO installer (name, email, city, password) VALUES
('John Doe', 'john@example.com', 'New York', 'hashed_password_here'),
('Jane Smith', 'jane@example.com', 'Los Angeles', 'hashed_password_here'),
('Bob Johnson', 'bob@example.com', 'Chicago', 'hashed_password_here');
