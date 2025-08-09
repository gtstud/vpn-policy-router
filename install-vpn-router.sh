#!/bin/bash
# VPN Policy Router Installation Script
# Date: 2025-08-09 18:13:44

set -e

# Color codes for prettier output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print with timestamp
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Define directories
INSTALL_DIR="/opt/vpn-router"
CONFIG_DIR="/etc/vpn-router"
SYSTEMD_DIR="/etc/systemd/system"

# Create directories
log "Creating installation directories..."
mkdir -p ${INSTALL_DIR}
mkdir -p ${CONFIG_DIR}

# Install dependencies
log "Installing required packages..."
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y python3 python3-pip wireguard iproute2 nftables
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS
    yum install -y python3 python3-pip wireguard iproute2 nftables
elif [ -f /etc/arch-release ]; then
    # Arch Linux
    pacman -Sy python python-pip wireguard-tools iproute2 nftables
else
    warning "Unsupported distribution, please install Python 3, WireGuard, iproute2 and nftables manually"
fi

# Copy main script
log "Copying VPN router script..."
cp vpn-apply.py ${INSTALL_DIR}/
chmod +x ${INSTALL_DIR}/vpn-apply.py

# Copy systemd service file
log "Setting up systemd service..."
cp vpn-router.service ${SYSTEMD_DIR}/

# Handle configuration files - don't overwrite existing ones
log "Setting up configuration files..."

# VPN definitions
if [ -f "${CONFIG_DIR}/vpn-definitions.json" ]; then
    warning "Existing vpn-definitions.json found. Not overwriting."
    # Copy example as reference with timestamp
    cp example-configs/vpn-definitions.json "${CONFIG_DIR}/vpn-definitions.json.example-$(date +%Y%m%d%H%M%S)"
    success "Saved example vpn-definitions.json as reference"
else
    cp example-configs/vpn-definitions.json ${CONFIG_DIR}/
    success "Installed default vpn-definitions.json"
    warning "Please update vpn-definitions.json with your VPN connection details"
fi

# Client assignments
if [ -f "${CONFIG_DIR}/vpn-clients.json" ]; then
    warning "Existing vpn-clients.json found. Not overwriting."
    # Copy example as reference with timestamp
    cp example-configs/vpn-clients.json "${CONFIG_DIR}/vpn-clients.json.example-$(date +%Y%m%d%H%M%S)"
    success "Saved example vpn-clients.json as reference"
else
    cp example-configs/vpn-clients.json ${CONFIG_DIR}/
    success "Installed default vpn-clients.json"
    warning "Please update vpn-clients.json with your client assignments"
fi

# Set appropriate permissions
log "Setting permissions..."
chown -R root:root ${INSTALL_DIR}
chmod -R 755 ${INSTALL_DIR}
chown -R root:root ${CONFIG_DIR}
chmod -R 600 ${CONFIG_DIR}/*.json
chmod 700 ${CONFIG_DIR}

# Enable systemd service
log "Enabling systemd service..."
systemctl daemon-reload
systemctl enable vpn-router.service

# Create directories for routing tables
log "Setting up routing table directory..."
mkdir -p /etc/iproute2/rt_tables.d/

log "Installation completed!"
log "------------------------------------"
log "Next steps:"
log "1. Edit ${CONFIG_DIR}/vpn-definitions.json with your VPN connection details"
log "2. Edit ${CONFIG_DIR}/vpn-clients.json with your client assignments"
log "3. Run 'systemctl start vpn-router' to apply the configuration"
log "4. Check status with 'systemctl status vpn-router'"
log "------------------------------------"

# Offer to validate configuration
read -p "Would you like to validate your configuration now? (y/n): " validate
if [[ $validate == "y" || $validate == "Y" ]]; then
    log "Validating configuration..."
    ${INSTALL_DIR}/vpn-apply.py --validate
    if [ $? -eq 0 ]; then
        success "Configuration validation successful!"
        
        read -p "Would you like to start the VPN router service now? (y/n): " start_service
        if [[ $start_service == "y" || $start_service == "Y" ]]; then
            log "Starting VPN router service..."
            systemctl start vpn-router.service
            systemctl status vpn-router.service
        else
            log "You can start the service later with 'systemctl start vpn-router'"
        fi
    else
        error "Configuration validation failed. Please check your configuration files."
    fi
else
    log "You can validate your configuration later with '${INSTALL_DIR}/vpn-apply.py --validate'"
fi

success "VPN Policy Router installation complete!"