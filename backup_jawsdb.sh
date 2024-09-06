#!/bin/bash

# Get the JAWSDB_URL
JAWSDB_URL=$(heroku config:get JAWSDB_URL)

# Parse the JAWSDB_URL
DB_USER=$(echo $JAWSDB_URL | cut -d: -f2 | cut -d/ -f3)
DB_PASSWORD=$(echo $JAWSDB_URL | cut -d: -f3 | cut -d@ -f1)
DB_HOST=$(echo $JAWSDB_URL | cut -d@ -f2 | cut -d: -f1)
DB_PORT=$(echo $JAWSDB_URL | cut -d: -f4 | cut -d/ -f1)
DB_NAME=$(echo $JAWSDB_URL | cut -d/ -f4)

# Perform the backup
BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
mysqldump --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME > $BACKUP_FILE

echo "Backup completed: $BACKUP_FILE"

# Optional: Upload the backup file to a storage service (e.g., AWS S3)
# aws s3 cp $BACKUP_FILE s3://your-bucket-name/

# Clean up
rm $BACKUP_FILE