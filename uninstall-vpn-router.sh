#!/bin/bash
#
# VPN Router Uninstallation Script
#
# This script safely removes all components of the VPN Router system.

set -e

# --- Constants ---
CONFIG_DIR="/etc/vpn-router"
SCRIPT_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SCRIPTS_TO_REMOVE=("vpn-apply.py" "vpn-assign.py")
UNITS_TO_REMOVE=("vpn-router.service" "vpn-router.timer")

# --- UI Functions ---
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- Main Uninstall Logic ---

# 1. Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root. Please run with sudo."
    exit 1
fi

log "Starting VPN Router uninstallation..."

# 2. Stop and disable systemd units
log "Stopping and disabling systemd units..."
# Stop the timer first
if systemctl list-units --quiet --all -t timer | grep -Fq 'vpn-router.timer'; then
    systemctl stop vpn-router.timer
    systemctl disable vpn-router.timer
    log "Stopped and disabled vpn-router.timer."
else
    warning "vpn-router.timer not found, skipping."
fi

# 3. Remove systemd unit files
log "Removing systemd unit files..."
for unit in "${UNITS_TO_REMOVE[@]}"; do
    unit_path="${SYSTEMD_DIR}/${unit}"
    if [ -f "$unit_path" ]; then
        rm -f "$unit_path"
        log "Removed ${unit_path}"
    else
        warning "Systemd unit file ${unit} not found, skipping."
    fi
done

# 4. Reload systemd daemon to apply changes
log "Reloading systemd daemon..."
systemctl daemon-reload

# 5. Remove installed scripts
log "Removing installed scripts from ${SCRIPT_DIR}..."
for script in "${SCRIPTS_TO_REMOVE[@]}"; do
    script_path="${SCRIPT_DIR}/${script}"
    if [ -f "$script_path" ]; then
        rm -f "$script_path"
        log "Removed ${script_path}"
    else
        warning "Script ${script} not found, skipping."
    fi
done

# 6. Prompt for configuration directory removal
log "Uninstallation of system files complete."
warning "Your configuration files in ${CONFIG_DIR} have not been touched."
read -p "Do you want to PERMANENTLY DELETE the configuration directory? [y/N] " -r
echo # Move to a new line

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -d "${CONFIG_DIR}" ]; then
        log "Removing configuration directory ${CONFIG_DIR}..."
        rm -rf "${CONFIG_DIR}"
        log "Configuration directory removed."
    else
        warning "Configuration directory ${CONFIG_DIR} not found."
    fi
else
    log "Your configuration files have been kept in ${CONFIG_DIR}."
fi

log "VPN Router uninstallation finished."
