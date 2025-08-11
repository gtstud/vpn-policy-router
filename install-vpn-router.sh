#!/bin/bash
#
# VPN Router Installation Script
#
# This script installs and configures the VPN Router system.
#
# Created by: gtstud
# Date: 2025-08-09 21:01:09

set -e

# Constants
CONFIG_DIR="/etc/vpn-router"
SCRIPT_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# ANSI colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'  # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

# Check for required commands
check_requirements() {
    log "Checking system requirements..."
    
    REQUIRED_COMMANDS=("ip" "wg" "getent" "systemctl" "networkctl" "python3" "firewall-cmd" "nft")
    
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            error "Please install the necessary packages and try again."
            exit 1
        fi
    done
    
    # Check Python version (3.6+ required)
    PYTHON_VERSION=$(python3 --version | cut -d ' ' -f 2)
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d '.' -f 1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d '.' -f 2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 6 ]); then
        error "Python 3.6+ is required (found $PYTHON_VERSION)"
        exit 1
    fi
    
    log "All requirements satisfied"
}

# Check for conflicts with existing system configuration
check_for_conflicts() {
    log "Checking for conflicts with existing system configuration..."
    
    # Extract ranges from config if it exists
    if [ -f "${CONFIG_DIR}/vpn-definitions.json" ]; then
        # Use grep and sed to extract ranges (since jq might not be installed)
        MIN_TABLE_ID=$(grep -o '"min": *[0-9]*' "${CONFIG_DIR}/vpn-definitions.json" | sed 's/.*: *//' || echo "7001")
        MAX_TABLE_ID=$(grep -o '"max": *[0-9]*' "${CONFIG_DIR}/vpn-definitions.json" | sed 's/.*: *//' || echo "7200")
        NETWORK_PREFIX=$(grep -o '"prefix": *"[^"]*"' "${CONFIG_DIR}/vpn-definitions.json" | sed 's/.*: *"//' | sed 's/"//' || echo "10.239")
    else
        # Default ranges for new installation
        MIN_TABLE_ID=7001
        MAX_TABLE_ID=7200
        NETWORK_PREFIX="10.239"
    fi
    
    # Check for routing tables in our range
    if grep -qE "^${MIN_TABLE_ID}|^${MAX_TABLE_ID}" /etc/iproute2/rt_tables 2>/dev/null; then
        if [ -f "${CONFIG_DIR}/vpn-definitions.json" ]; then
            warning "Found routing tables in VPN router range (${MIN_TABLE_ID}-${MAX_TABLE_ID}). This is expected for an existing installation."
        else
            error "Found existing routing tables in the range ${MIN_TABLE_ID}-${MAX_TABLE_ID}. These conflict with VPN router."
            error "Please choose a different routing table range or remove the conflicting tables."
            return 1
        fi
    fi
    
    # Check for IP addresses in our range
    if ip addr | grep -q "${NETWORK_PREFIX}\."; then
        if [ -f "${CONFIG_DIR}/vpn-definitions.json" ]; then
            warning "Found IP addresses in VPN router range (${NETWORK_PREFIX}). This is expected for an existing installation."
        else
            error "Found existing IP addresses in the range ${NETWORK_PREFIX}. These conflict with VPN router."
            error "Please choose a different IP range or remove the conflicting addresses."
            return 1
        fi
    fi
    
    return 0
}

# Create configuration directory and default config files
create_config_dir() {
    log "Creating configuration directory..."
    mkdir -p "$CONFIG_DIR"
    
    # Create default VPN definitions
    log "Creating default VPN definitions..."
    cat > "${CONFIG_DIR}/vpn-definitions.json.default" << EOF
{
  "system_config": {
    "routing_table_id_range": {
      "min": 7001,
      "max": 7200
    },
    "veth_network_range": {
      "prefix": "10.239"
    }
  },
  "vpn_connections": []
}
EOF

    # Create default client assignments
    log "Creating default client assignments..."
    cat > "${CONFIG_DIR}/vpn-clients.json.default" << EOF
{
  "assignments": []
}
EOF

    # If no actual config files exist, copy the defaults
    if [ ! -f "${CONFIG_DIR}/vpn-definitions.json" ]; then
        log "No VPN definitions found, creating from default template"
        cp "${CONFIG_DIR}/vpn-definitions.json.default" "${CONFIG_DIR}/vpn-definitions.json"
    else
        log "Existing VPN definitions found, keeping current configuration"
    fi
    
    if [ ! -f "${CONFIG_DIR}/vpn-clients.json" ]; then
        log "No client assignments found, creating from default template"
        cp "${CONFIG_DIR}/vpn-clients.json.default" "${CONFIG_DIR}/vpn-clients.json"
    else
        log "Existing client assignments found, keeping current configuration"
    fi
    
    # Set correct permissions
    chmod 600 "${CONFIG_DIR}"/*.json*
    chown root:root "${CONFIG_DIR}"/*.json*
}

# Install the VPN router scripts
install_scripts() {
    log "Installing VPN router scripts..."
    
    # Verify that scripts exist in the current directory
    if [ ! -f "vpn-apply.py" ] || [ ! -f "vpn-router-check.py" ] || [ ! -f "vpn-assign.py" ]; then
        error "Required script files not found in the current directory"
        error "Make sure vpn-apply.py, vpn-router-check.py, and vpn-assign.py are in the same directory as this install script"
        exit 1
    fi
    
    # Copy scripts to the destination directory
    cp "vpn-apply.py" "${SCRIPT_DIR}/"
    cp "vpn-router-check.py" "${SCRIPT_DIR}/"
    cp "vpn-assign.py" "${SCRIPT_DIR}/"
    
    # Make scripts executable
    chmod 755 "${SCRIPT_DIR}/vpn-apply.py"
    chmod 755 "${SCRIPT_DIR}/vpn-router-check.py"
    chmod 755 "${SCRIPT_DIR}/vpn-assign.py"
    
    log "VPN router scripts installed successfully"
}

# Install systemd service and timer
install_systemd_units() {
    log "Installing systemd service and timer files..."
    
    # Verify that systemd unit files exist in the current directory
    if [ ! -f "vpn-router.service" ] || [ ! -f "vpn-router.timer" ]; then
        error "Required systemd unit files not found in the current directory"
        error "Make sure vpn-router.service and vpn-router.timer are in the same directory as this install script"
        exit 1
    fi
    
    # Copy systemd unit files
    cp "vpn-router.service" "${SYSTEMD_DIR}/"
    cp "vpn-router.timer" "${SYSTEMD_DIR}/"
    
    # Set correct permissions
    chmod 644 "${SYSTEMD_DIR}/vpn-router.service"
    chmod 644 "${SYSTEMD_DIR}/vpn-router.timer"
    
    # Reload systemd to recognize the new units
    systemctl daemon-reload
    
    # Enable and start the timer
    log "Enabling and starting vpn-router.timer"
    systemctl enable vpn-router.timer
    systemctl start vpn-router.timer
    
    log "Systemd service and timer installed and activated successfully"
    log "The vpn-router timer will run the VPN configuration periodically"
}

# Run the installation
run_installation() {
    log "Starting VPN Router installation..."
    
    check_requirements
    check_for_conflicts || exit 1
    create_config_dir
    install_scripts
    install_systemd_units
    
    log "VPN Router installation completed successfully!"
    log "You can now configure your VPN connections in ${CONFIG_DIR}/vpn-definitions.json"
    log "and client assignments in ${CONFIG_DIR}/vpn-clients.json"
}

run_installation