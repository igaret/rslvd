#!/bin/bash

# RSLVD DNS Backup Script

set -e

# Configuration
BACKUP_DIR="/var/backups/rslvd"
CONFIG_DIR="/etc/rslvd"
LOG_DIR="/var/log/rslvd"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_info "Starting RSLVD DNS backup..."

# Backup configuration and zones
tar -czf "$BACKUP_DIR/rslvd-config-$TIMESTAMP.tar.gz" \
    -C "$(dirname $CONFIG_DIR)" \
    "$(basename $CONFIG_DIR)"

# Backup logs (last 7 days)
find "$LOG_DIR" -name "*.log" -mtime -7 -exec \
    tar -czf "$BACKUP_DIR/rslvd-logs-$TIMESTAMP.tar.gz" {} +

# Cleanup old backups
find "$BACKUP_DIR" -name "rslvd-*.tar.gz" -mtime +$RETENTION_DAYS -delete

log_info "Backup completed: $BACKUP_DIR/rslvd-config-$TIMESTAMP.tar.gz"
All Files Status Summary