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

# Config file paths
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"

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

def list_vpns_and_clients() -> None:
    """List available VPNs and client assignments"""
    try:
        with open(VPN_DEFINITIONS_PATH, 'r') as f:
            vpn_defs = json.load(f)
            
        with open(VPN_CLIENTS_PATH, 'r') as f:
            client_assignments = json.load(f)
            
        # Print available VPNs
        print("\n=== Available VPN Connections ===")
        print(f"{'Name':<15} {'Description':<30}")
        print("-" * 45)
        
        for vpn in vpn_defs.get("vpn_connections", []):
            print(f"{vpn.get('name', 'N/A'):<15} {vpn.get('description', 'N/A'):<30}")
        
        # Print client assignments
        print("\n=== Client Assignments ===")
        print(f"{'Display Name':<20} {'Identifier':<20} {'Assigned VPN':<15} {'Expires':<25}")
        print("-" * 80)
        
        now = datetime.now(timezone.utc)
        
        for client in client_assignments.get("assignments", []):
            # Determine the identifier (hostname or IP)
            identifier = client.get("hostname") or client.get("ip_address") or "N/A"
            
            # Determine expiry
            expiry = client.get("assignment_expiry")
            if expiry:
                try:
                    expiry_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    if expiry_date < now:
                        expiry_display = f"{expiry} (EXPIRED)"
                    else:
                        time_left = expiry_date - now
                        days_left = time_left.days
                        expiry_display = f"{expiry} ({days_left} days left)"
                except ValueError:
                    expiry_display = f"{expiry} (INVALID FORMAT)"
            else:
                expiry_display = "Never"
                
            # Display with color if expired
            if expiry and "EXPIRED" in expiry_display:
                print(f"{client.get('display_name', 'N/A'):<20} {identifier:<20} {client.get('assigned_vpn', 'N/A'):<15} \033[0;31m{expiry_display}\033[0m")
            else:
                print(f"{client.get('display_name', 'N/A'):<20} {identifier:<20} {client.get('assigned_vpn', 'N/A'):<15} {expiry_display:<25}")
    
    except FileNotFoundError as e:
        print(f"Error: Configuration file not found - {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error listing VPNs and clients: {e}")
        sys.exit(1)

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


def apply_configuration():
    """Apply the VPN router configuration"""
    try:
        # Call vpn-apply script
        logger.info("Applying VPN router configuration...")
        subprocess.run(["/usr/local/bin/vpn-apply.py"], check=True)
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
    manage_group.add_argument("--remove", metavar="IDENTIFIER", help="Remove the assignment for the specified client (IP or hostname)")
    manage_group.add_argument("--remove-all", action="store_true", help="Remove all client assignments")
    
    args = parser.parse_args()
    
    # Handle management actions
    if args.list:
        list_vpns_and_clients()
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
