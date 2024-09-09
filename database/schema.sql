CREATE DATABASE k5whq2461jtx4q01;
USE k5whq2461jtx4q01;

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


SET GLOBAL max_user_connections = 20;

GRANT USAGE ON *.* TO 'ly5go5v83actn4h7'@'%' WITH MAX_USER_CONNECTIONS 20;