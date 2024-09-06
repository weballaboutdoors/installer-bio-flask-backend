#!/bin/bash

# Parse the JAWSDB_URL
DB_USER=$(echo $JAWSDB_URL | cut -d: -f2 | cut -d/ -f3)
DB_PASSWORD=$(echo $JAWSDB_URL | cut -d: -f3 | cut -d@ -f1)
DB_HOST=$(echo $JAWSDB_URL | cut -d@ -f2 | cut -d: -f1)
DB_PORT=$(echo $JAWSDB_URL | cut -d: -f4 | cut -d/ -f1)
DB_NAME=$(echo $JAWSDB_URL | cut -d/ -f4)

# Print parsed values for debugging (remove in production)
echo "Host: $DB_HOST"
echo "Port: $DB_PORT"
echo "User: $DB_USER"
echo "Password: $DB_PASSWORD"
echo "Database: $DB_NAME"

# Perform the backup
BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"

# Use a single mysql connection to perform all operations
mysql --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME << EOF > $BACKUP_FILE
SET group_concat_max_len = 1024 * 1024 * 1024;

SELECT CONCAT(
    'DROP TABLE IF EXISTS \`', table_name, '\`;',
    '\n',
    'CREATE TABLE \`', table_name, '\` (',
    GROUP_CONCAT(CONCAT(
        '\n  \`', column_name, '\` ', column_type,
        IF(is_nullable = 'NO', ' NOT NULL', ''),
        IF(column_default IS NOT NULL, CONCAT(' DEFAULT \'', column_default, '\''), ''),
        IF(extra != '', CONCAT(' ', extra), '')
    ) ORDER BY ordinal_position SEPARATOR ','),
    '\n);'
) AS create_table
FROM information_schema.columns
WHERE table_schema = DATABASE()
GROUP BY table_name;

SELECT CONCAT('SELECT * FROM \`', table_name, '\`;')
FROM information_schema.tables
WHERE table_schema = DATABASE();
EOF

echo "Backup completed: $BACKUP_FILE"
echo "Backup contents:"
cat $BACKUP_FILE