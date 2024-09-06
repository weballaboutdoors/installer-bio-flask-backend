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

# Use mysqldump to create the backup
mysqldump --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD --databases $DB_NAME --add-drop-table --no-tablespaces > $BACKUP_FILE

echo "Backup completed: $BACKUP_FILE"
echo "Backup contents:"
cat $BACKUP_FILE