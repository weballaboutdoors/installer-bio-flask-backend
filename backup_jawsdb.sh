#!/bin/bash

# The JAWSDB_URL is already set as an environment variable in Heroku
# so we don't need to use the heroku command to get it

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

# Use mysql instead of mysqldump
mysql --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME -e "
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
GROUP BY table_name;" > $BACKUP_FILE

for table in $(mysql --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME -e "SHOW TABLES;" | tail -n +2); do
    echo "Backing up table: $table"
    mysql --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME -e "SELECT * FROM \`$table\`;" >> $BACKUP_FILE
done

echo "Backup completed: $BACKUP_FILE"
echo "Backup contents:"
cat $BACKUP_FILE