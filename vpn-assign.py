#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VPN Client Assignment Script
---------------------------
This script manages client assignments to VPNs.
Version: 1.0
Date: 2025-08-09
"""

import argparse
import fcntl
import json
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger("vpn-router")

# Constants
CONFIG_DIR = Path("/etc/vpn-router")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
VPN_APPLY_PATH = Path("/usr/local/bin/vpn-apply.py")

def parse_duration(duration_str: str) -> Optional[datetime]:
    """Parse a duration string into a future datetime"""
    if not duration_str:
        return None
        
    now = datetime.now(timezone.utc)
    parts = duration_str.lower().split()
    
    if len(parts) != 2:
        logger.error("Invalid duration format. Expected format: '30 days'")
        return None
    
    try:
        value = int(parts[0])
        unit = parts[1]
    except ValueError:
        logger.error("Invalid duration value. Expected a number followed by a unit")
        return None
    
    if unit.endswith('s'):
        unit = unit[:-1]
    
    if unit == "minute" or unit == "min":
        return now + timedelta(minutes=value)
    elif unit == "hour" or unit == "hr":
        return now + timedelta(hours=value)
    elif unit == "day":
        return now + timedelta(days=value)
    elif unit == "week" or unit == "wk":
        return now + timedelta(weeks=value)
    elif unit == "month" or unit == "mo":
        # Approximate a month as 30 days
        return now + timedelta(days=value * 30)
    else:
        logger.error("Unknown duration unit. Supported units: minute, hour, day, week, month")
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
                expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                if expiry_dt < now:
                    expiry_str = "EXPIRED"
                else:
                    expiry_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                expiry_str = "Never (permanent)"
            
            print(f"{client.get('display_name', 'N/A'):<20} {identifier:<20} {client.get('assigned_vpn', 'Default'):<15} {expiry_str:<25}")
            
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error reading configuration: {e}")
        sys.exit(1)

def update_client_assignment(args) -> None:
    """Create or update a client assignment"""
    # Validate arguments
    if args.vpn and args.vpn.lower() == "none":
        vpn_name = None
    else:
        vpn_name = args.vpn
        
    # Calculate expiry
    if args.duration:
        expiry_dt = parse_duration(args.duration)
        if not expiry_dt:
            logger.error("Invalid duration format")
            sys.exit(1)
        expiry = expiry_dt.isoformat().replace("+00:00", "Z")
    else:
        expiry = None
    
    # Acquire a lock on the clients file
    try:
        with open(VPN_CLIENTS_PATH, 'r+') as f:
            # Get an exclusive lock
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            
            try:
                client_assignments = json.load(f)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in clients file")
                sys.exit(1)
            
            # Find existing client or create new one
            client_found = False
            for i, client in enumerate(client_assignments.get("assignments", [])):
                if client.get("display_name") == args.display_name:
                    client_found = True
                    
                    # Cannot update hostname or IP for existing clients
                    if args.ip or args.hostname:
                        logger.error("Cannot update hostname or IP for existing clients")
                        sys.exit(1)
                    
                    # Update VPN assignment and expiry
                    client_assignments["assignments"][i]["assigned_vpn"] = vpn_name
                    client_assignments["assignments"][i]["assignment_expiry"] = expiry
                    logger.info(f"Updated client {args.display_name}")
                    break
            
            # Create new client if not found
            if not client_found:
                if not args.ip and not args.hostname:
                    logger.error("New clients require either --ip or --hostname")
                    sys.exit(1)
                
                if args.ip and args.hostname:
                    logger.error("Cannot specify both --ip and --hostname")
                    sys.exit(1)
                
                new_client = {
                    "display_name": args.display_name,
                    "hostname": args.hostname,
                    "ip_address": args.ip,
                    "assigned_vpn": vpn_name,
                    "assignment_expiry": expiry
                }
                
                if "assignments" not in client_assignments:
                    client_assignments["assignments"] = []
                
                client_assignments["assignments"].append(new_client)
                logger.info(f"Created new client {args.display_name}")
            
            # Write updated configuration
            f.seek(0)
            f.truncate()
            json.dump(client_assignments, f, indent=2)
            
            # Release lock
            fcntl.flock(f, fcntl.LOCK_UN)
    
    except FileNotFoundError:
        logger.error(f"Clients file not found: {VPN_CLIENTS_PATH}")
        sys.exit(1)
    except IOError:
        logger.error("Could not acquire lock on clients file")
        sys.exit(1)
    
    # Apply the changes
    try:
        subprocess.run([str(VPN_APPLY_PATH)], check=True)
        logger.info("Configuration applied successfully")
    except subprocess.CalledProcessError:
        logger.error("Failed to apply configuration")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="VPN Client Assignment Tool")
    
    parser.add_argument("--list", action="store_true", help="List available VPNs and current client assignments")
    
    # Client assignment options
    parser.add_argument("--display-name", help="Unique display name for the client")
    parser.add_argument("--vpn", help="VPN to assign to the client (use 'none' for default routing)")
    parser.add_argument("--ip", help="Static IP address of the client")
    parser.add_argument("--hostname", help="DNS hostname of the client")
    parser.add_argument("--duration", help="Assignment duration (e.g., '30 days')")
    
    args = parser.parse_args()
    
    # Default to list mode if no arguments provided
    if len(sys.argv) == 1:
        list_vpns_and_clients()
        sys.exit(0)
    
    # Handle list mode
    if args.list:
        list_vpns_and_clients()
        sys.exit(0)
    
    # Handle update/create mode
    if args.display_name and args.vpn:
        update_client_assignment(args)
    else:
        parser.error("--display-name and --vpn are required for updating client assignments")

if __name__ == "__main__":
    main()