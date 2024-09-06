#!/bin/bash

# Parse the JAWSDB_URL
DB_USER=$(echo $JAWSDB_URL | cut -d: -f2 | cut -d/ -f3)
DB_PASSWORD=$(echo $JAWSDB_URL | cut -d: -f3 | cut -d@ -f1)
DB_HOST=$(echo $JAWSDB_URL | cut -d@ -f2 | cut -d: -f1)
DB_PORT=$(echo $JAWSDB_URL | cut -d: -f4 | cut -d/ -f1)
DB_NAME=$(echo $JAWSDB_URL | cut -d/ -f4)

# Create test table if it doesn't exist
mysql -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS test (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255)
);
EOF

# Insert test data
mysql -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME <<EOF
INSERT INTO test (name) VALUES ('Test Data');
EOF

echo "Test data inserted successfully."

# Display the contents of the test table
echo "Contents of test table:"
mysql -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME -e "SELECT * FROM test;"