#!/usr/bin/env python3
"""
VPN Policy Router Assignment Tool
This script manages client assignments to VPN connections
"""

import os
import sys
import re
import json
import argparse
import logging
import ipaddress
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('vpn-assign')

# Base directories
CONFIG_DIR = Path("/etc/vpn-router")
SYSTEMD_DIR = Path("/etc/systemd/system")

# Config file paths
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
TIMER_PATH = SYSTEMD_DIR / "vpn-assign-cleanup.timer"
SERVICE_PATH = SYSTEMD_DIR / "vpn-assign-cleanup.service"

# Time units for duration parsing
TIME_UNITS = {
    's': 1,
    'm': 60,
    'h': 3600,
    'd': 86400,
}


def load_json(path):
    """Load JSON from file"""
    try:
        if path.exists():
            with open(path, 'r') as f:
                return json.load(f)
        else:
            logger.warning(f"Config file not found: {path}")
            return {}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {path}")
        return {}
    except Exception as e:
        logger.error(f"Error loading config file {path}: {e}")
        return {}


def save_json(path, data):
    """Save JSON to file"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving to {path}: {e}")
        return False


def parse_duration(duration_str):
    """Parse duration string with units (e.g., '1h', '30m', '1d')"""
    if not duration_str:
        return None
        
    # If it's just a number, assume seconds
    if duration_str.isdigit():
        return int(duration_str)
        
    match = re.match(r'^(\d+)([smhd])$', duration_str.lower())
    if match:
        value = int(match.group(1))
        unit = match.group(2)
        return value * TIME_UNITS[unit]
        
    raise ValueError(f"Invalid duration format: {duration_str}. Use format like '30s', '5m', '2h', '1d'")


def format_expiry(expiry_timestamp):
    """Format expiry timestamp for display"""
    if not expiry_timestamp:
        return "Never (permanent)"
        
    try:
        # If it's an ISO format string, parse it
        if isinstance(expiry_timestamp, str):
            expiry_time = datetime.fromisoformat(expiry_timestamp.replace('Z', '+00:00'))
        else:
            expiry_time = datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc)
            
        now = datetime.now(tz=timezone.utc)
        
        if expiry_time < now:
            return "Expired"
            
        # Calculate remaining time
        remaining = expiry_time - now
        days = remaining.days
        hours, remainder = divmod(remaining.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # Format expiry string
        expiry_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Add remaining time
        if days > 0:
            remaining_str = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            remaining_str = f"{hours}h {minutes}m"
        elif minutes > 0:
            remaining_str = f"{minutes}m {seconds}s"
        else:
            remaining_str = f"{seconds}s"
            
        return f"{expiry_str} (remaining: {remaining_str})"
    except Exception as e:
        return f"Error parsing expiry: {e}"


def find_client_by_identifier(identifier):
    """Find a client by IP or hostname in the assignments list"""
    clients = load_json(VPN_CLIENTS_PATH)
    
    if "assignments" not in clients:
        return None
        
    for assignment in clients["assignments"]:
        if assignment.get("ip_address") == identifier or assignment.get("hostname") == identifier:
            return assignment
            
    return None


def list_assignments():
    """List all client VPN assignments"""
    clients = load_json(VPN_CLIENTS_PATH)
    vpn_defs = load_json(VPN_DEFINITIONS_PATH)
    
    if "assignments" not in clients or not clients["assignments"]:
        print("No client assignments found")
        return
        
    # Get a mapping of VPN names for display
    vpn_names = {}
    if "vpn_connections" in vpn_defs:
        for vpn in vpn_defs["vpn_connections"]:
            if "name" in vpn:
                vpn_names[vpn["name"]] = vpn
    
    # Print header
    print("\nCurrent VPN Assignments:")
    print("-" * 100)
    print(f"{'Display Name':<25} {'Hostname':<20} {'IP Address':<16} {'VPN':<15} {'Expiry':<30}")
    print("-" * 100)
    
    # Sort assignments by expiry (permanent ones last)
    def get_expiry_key(a):
        expiry = a.get("assignment_expiry")
        if not expiry:
            return float('inf')
        if isinstance(expiry, str):
            try:
                return datetime.fromisoformat(expiry.replace('Z', '+00:00')).timestamp()
            except:
                return float('inf')
        return expiry
        
    sorted_assignments = sorted(
        clients["assignments"],
        key=get_expiry_key
    )
    
    # Print each assignment
    for assignment in sorted_assignments:
        display_name = assignment.get("display_name", "")
        hostname = assignment.get("hostname", "") or ""
        ip_address = assignment.get("ip_address", "") or ""
        vpn_name = assignment.get("assigned_vpn", "direct")
        expiry = format_expiry(assignment.get("assignment_expiry"))
        
        print(f"{display_name:<25} {hostname:<20} {ip_address:<16} {vpn_name:<15} {expiry:<30}")
    
    print("-" * 100)


def create_assignment(ip_address, hostname, vpn_name, expiry=None, display_name=None):
    """Create a new VPN assignment for a client"""
    if not ip_address and not hostname:
        logger.error("Either IP address or hostname is required")
        return False
        
    if not vpn_name:
        logger.error("VPN name is required")
        return False
        
    # Load configs
    clients = load_json(VPN_CLIENTS_PATH)
    vpn_defs = load_json(VPN_DEFINITIONS_PATH)
    
    # Initialize clients structure if needed
    if not clients:
        clients = {"assignments": []}
        
    if "assignments" not in clients:
        clients["assignments"] = []
        
    # Check if VPN exists
    valid_vpns = [vpn["name"] for vpn in vpn_defs.get("vpn_connections", [])]
    if vpn_name != "direct" and vpn_name not in valid_vpns:
        logger.error(f"Invalid VPN name: {vpn_name}. Valid options: {', '.join(valid_vpns)} or 'direct'")
        return False
        
    # Check if client already exists - match by either IP or hostname
    existing_idx = None
    client_identifier = ip_address or hostname
    
    for i, assignment in enumerate(clients["assignments"]):
        if (ip_address and assignment.get("ip_address") == ip_address) or \
           (hostname and assignment.get("hostname") == hostname):
            existing_idx = i
            break
            
    # Create assignment object
    assignment = {
        "display_name": display_name or client_identifier,
        "hostname": hostname,
        "ip_address": ip_address,
        "assigned_vpn": vpn_name,
    }
    
    if expiry is not None:
        # Format in ISO 8601 with UTC timezone
        if isinstance(expiry, float) or isinstance(expiry, int):
            dt = datetime.fromtimestamp(expiry, tz=timezone.utc)
            assignment["assignment_expiry"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            assignment["assignment_expiry"] = expiry
    else:
        assignment["assignment_expiry"] = None
        
    # Update or append
    if existing_idx is not None:
        clients["assignments"][existing_idx] = assignment
        logger.info(f"Updated assignment for {client_identifier} to VPN {vpn_name}")
    else:
        clients["assignments"].append(assignment)
        logger.info(f"Created new assignment for {client_identifier} to VPN {vpn_name}")
        
    # Save updated config
    if save_json(VPN_CLIENTS_PATH, clients):
        logger.info("Assignment saved successfully")
        
        # Apply the configuration if not a direct assignment
        if vpn_name != "direct":
            apply_configuration()
            
        return True
    else:
        logger.error("Failed to save assignment")
        return False


def remove_assignment(identifier):
    """Remove a client's VPN assignment by IP or hostname"""
    if not identifier:
        logger.error("Client identifier (IP or hostname) is required")
        return False
        
    # Load config
    clients = load_json(VPN_CLIENTS_PATH)
    
    if "assignments" not in clients:
        logger.error(f"No assignments found")
        return False
        
    # Find and remove the assignment
    found = False
    for i, assignment in enumerate(clients["assignments"]):
        if assignment.get("ip_address") == identifier or assignment.get("hostname") == identifier:
            logger.info(f"Found assignment for {identifier}: VPN={assignment.get('assigned_vpn')}")
            del clients["assignments"][i]
            found = True
            break
            
    if not found:
        logger.error(f"No assignment found for client {identifier}")
        return False
        
    # Save updated config
    if save_json(VPN_CLIENTS_PATH, clients):
        logger.info(f"Removed assignment for client {identifier}")
        
        # Apply configuration to ensure VPN state matches assignments
        apply_configuration()
        
        return True
    else:
        logger.error("Failed to save assignment changes")
        return False


def remove_all_assignments():
    """Remove all client VPN assignments"""
    # Load config
    clients = load_json(VPN_CLIENTS_PATH)
    
    if "assignments" not in clients or not clients["assignments"]:
        logger.info("No assignments to remove")
        return True
        
    # Count assignments
    count = len(clients["assignments"])
    
    # Clear all assignments
    clients["assignments"] = []
    
    # Save updated config
    if save_json(VPN_CLIENTS_PATH, clients):
        logger.info(f"Removed all {count} client assignments")
        
        # Apply configuration to ensure VPN state matches assignments
        apply_configuration()
        
        return True
    else:
        logger.error("Failed to save assignment changes")
        return False


def cleanup_expired():
    """Clean up expired VPN assignments"""
    # Load config
    clients = load_json(VPN_CLIENTS_PATH)
    
    if "assignments" not in clients:
        logger.debug("No assignments found")
        return True
        
    current_time = datetime.now(tz=timezone.utc)
    expired = []
    active = []
    
    # Find expired assignments
    for assignment in clients["assignments"]:
        expiry = assignment.get("assignment_expiry")
        
        if not expiry:
            # No expiry means permanent
            active.append(assignment)
            continue
            
        # Parse the expiry time
        if isinstance(expiry, str):
            try:
                expiry_dt = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                if expiry_dt < current_time:
                    expired.append(assignment)
                else:
                    active.append(assignment)
            except ValueError:
                logger.warning(f"Invalid expiry format: {expiry}, treating as permanent")
                active.append(assignment)
        else:
            logger.warning(f"Unexpected expiry format: {expiry}, treating as permanent")
            active.append(assignment)
            
    if not expired:
        logger.debug("No expired assignments found")
        return True
        
    # Update with only active assignments
    clients["assignments"] = active
    
    # Save updated config
    if save_json(VPN_CLIENTS_PATH, clients):
        logger.info(f"Cleaned up {len(expired)} expired assignments")
        
        # List expired clients
        for exp in expired:
            identifier = exp.get('ip_address') or exp.get('hostname')
            logger.info(f"Expired: {identifier} (VPN: {exp.get('assigned_vpn')})")
            
        # Apply configuration to ensure VPN state matches assignments
        apply_configuration()
        
        return True
    else:
        logger.error("Failed to save assignment changes")
        return False


def install_cleanup_timer():
    """Install the cleanup timer for expired assignments"""
    # Create service file
    service_content = """[Unit]
Description=VPN Assignment Cleanup Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-assign --cleanup-expired
"""

    # Create timer file
    timer_content = """[Unit]
Description=VPN Assignment Cleanup Timer
After=network.target

[Timer]
OnBootSec=60
OnUnitActiveSec=300
AccuracySec=60

[Install]
WantedBy=timers.target
"""

    try:
        # Write service file
        with open(SERVICE_PATH, 'w') as f:
            f.write(service_content)
            
        # Write timer file
        with open(TIMER_PATH, 'w') as f:
            f.write(timer_content)
            
        # Enable and start timer
        subprocess.run(["systemctl", "enable", "--now", "vpn-assign-cleanup.timer"], check=True)
        logger.info("Cleanup timer installed and started")
        return True
    except Exception as e:
        logger.error(f"Failed to install cleanup timer: {e}")
        return False


def remove_cleanup_timer():
    """Remove the cleanup timer for expired assignments"""
    try:
        # Stop and disable timer
        subprocess.run(["systemctl", "disable", "--now", "vpn-assign-cleanup.timer"],
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
        # Remove files
        if os.path.exists(TIMER_PATH):
            os.unlink(TIMER_PATH)
            
        if os.path.exists(SERVICE_PATH):
            os.unlink(SERVICE_PATH)
            
        logger.info("Cleanup timer removed")
        return True
    except Exception as e:
        logger.error(f"Failed to remove cleanup timer: {e}")
        return False


def apply_configuration():
    """Apply the VPN router configuration"""
    try:
        # Call vpn-apply script
        logger.info("Applying VPN router configuration...")
        subprocess.run(["/usr/local/bin/vpn-apply"], check=True)
        logger.info("VPN router configuration applied successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to apply VPN configuration: {e}")
        return False
    except Exception as e:
        logger.error(f"Error applying VPN configuration: {e}")
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VPN Assignment Tool")
    
    # Client identifier options
    client_group = parser.add_argument_group('Client Identification')
    client_group.add_argument("--ip", help="Specify client by IP address")
    client_group.add_argument("--hostname", help="Specify client by hostname")
    client_group.add_argument("--display-name", help="Set a friendly display name for the client")
    
    # Assignment options
    assign_group = parser.add_argument_group('Assignment Options')
    assign_group.add_argument("--vpn", help="VPN name to assign the client to")
    assign_group.add_argument("--duration", help="Duration of assignment in seconds or with units (e.g., 30s, 5m, 2h, 1d)")
    assign_group.add_argument("--expire-at", help="Specific timestamp when the assignment expires (YYYY-MM-DD HH:MM:SS)")
    assign_group.add_argument("--permanent", action="store_true", help="Make the assignment permanent (never expires)")
    
    # Management options
    manage_group = parser.add_argument_group('Management Options')
    manage_group.add_argument("--list", action="store_true", help="List all client assignments")
    manage_group.add_argument("--cleanup-expired", action="store_true", help="Clean up expired assignments")
    manage_group.add_argument("--install-timer", action="store_true", help="Install the cleanup timer")
    manage_group.add_argument("--remove-timer", action="store_true", help="Remove the cleanup timer")
    manage_group.add_argument("--remove", metavar="IDENTIFIER", help="Remove the assignment for the specified client (IP or hostname)")
    manage_group.add_argument("--remove-all", action="store_true", help="Remove all client assignments")
    
    args = parser.parse_args()
    
    # Handle management actions
    if args.list:
        list_assignments()
        return
        
    if args.cleanup_expired:
        cleanup_expired()
        return
        
    if args.install_timer:
        install_cleanup_timer()
        return
        
    if args.remove_timer:
        remove_cleanup_timer()
        return
        
    if args.remove:
        remove_assignment(args.remove)
        return
        
    if args.remove_all:
        remove_all_assignments()
        return
        
    # For assignments, need client ID and VPN
    ip_address = args.ip
    hostname = args.hostname
    
    if not ip_address and not hostname:
        if args.vpn:
            logger.error("Client identification required. Specify --ip or --hostname.")
            return
        else:
            # If no specific action, show help
            parser.print_help()
            return
            
    if not args.vpn:
        logger.error("VPN name required. Specify --vpn.")
        return
        
    # Calculate expiry time
    expiry = None
    
    if args.permanent:
        expiry = None
    elif args.expire_at:
        try:
            expiry_dt = datetime.strptime(args.expire_at, "%Y-%m-%d %H:%M:%S")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            expiry = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            logger.error("Invalid expire-at format. Use YYYY-MM-DD HH:MM:SS")
            return
    elif args.duration:
        try:
            duration_seconds = parse_duration(args.duration)
            if duration_seconds:
                expiry_dt = datetime.now(tz=timezone.utc) + timedelta(seconds=duration_seconds)
                expiry = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError as e:
            logger.error(str(e))
            return
            
    # Create the assignment
    create_assignment(ip_address, hostname, args.vpn, expiry, args.display_name)


if __name__ == "__main__":
    main()