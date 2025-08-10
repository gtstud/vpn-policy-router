#!/usr/bin/env python3
"""
VPN Router Resource Check Script
This script checks for orphaned VPN router resources
"""

import os
import re
import sys
import json
import hashlib
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ANSI colors for output
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
RED = '\033[0;31m'
NC = '\033[0m'  # No Color

# Default resource ranges
DEFAULT_MIN_TABLE_ID = 7001
DEFAULT_MAX_TABLE_ID = 7200
DEFAULT_NETWORK_PREFIX = "10.239"

# Base directory
CONFIG_DIR = Path("/etc/vpn-router")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
NETWORKD_PATH = Path("/etc/systemd/network")


def print_colored(color, message):
    """Print colored message"""
    print(f"{color}{message}{NC}")


def load_config_ranges():
    """Load resource ranges from configuration"""
    min_table_id = DEFAULT_MIN_TABLE_ID
    max_table_id = DEFAULT_MAX_TABLE_ID
    network_prefix = DEFAULT_NETWORK_PREFIX
    
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                config = json.load(f)
                
            if "system_config" in config:
                sys_config = config["system_config"]
                if "routing_table_id_range" in sys_config:
                    min_table_id = sys_config["routing_table_id_range"].get("min", DEFAULT_MIN_TABLE_ID)
                    max_table_id = sys_config["routing_table_id_range"].get("max", DEFAULT_MAX_TABLE_ID)
                
                if "veth_network_range" in sys_config:
                    network_prefix = sys_config["veth_network_range"].get("prefix", DEFAULT_NETWORK_PREFIX)
        except Exception as e:
            print_colored(RED, f"Error loading configuration: {e}")
            
    return min_table_id, max_table_id, network_prefix


def get_active_vpns():
    """Get list of active VPN names from configuration"""
    active_vpns = []
    
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                config = json.load(f)
                
            active_vpns = [vpn["name"] for vpn in config.get("vpn_connections", [])]
        except Exception as e:
            print_colored(RED, f"Error loading VPN definitions: {e}")
            
    return active_vpns

def check_network_namespaces(active_vpns):
    """Check for orphaned network namespaces"""
    print_colored(GREEN, "Checking network namespaces...")
    orphaned_ns = []
    
    try:
        ns_output = subprocess.run(["ip", "netns", "list"], 
                                 capture_output=True, text=True).stdout
        
        for line in ns_output.splitlines():
            if not line.strip():
                continue
                
            # Extract namespace name
            ns_name = line.split(' ')[0].strip()
            
            # Check if it matches our pattern
            if ns_name.startswith("ns-"):
                vpn_name = ns_name[3:]  # Remove "ns-" prefix
                
                # Check if VPN is active
                if vpn_name not in active_vpns:
                    print_colored(YELLOW, f"Found orphaned namespace: {ns_name}")
                    orphaned_ns.append({
                        "name": ns_name,
                        "vpn_name": vpn_name
                    })
                    
    except Exception as e:
        print_colored(RED, f"Error checking network namespaces: {e}")
        
    return orphaned_ns

def check_routing_tables(active_vpns, min_table_id, max_table_id):
    """Check for orphaned routing tables"""
    print_colored(GREEN, "Checking routing tables...")
    orphaned_tables = []
    
    try:
        # Get all routing tables from /etc/iproute2/rt_tables
        rt_tables = {}
        if os.path.exists("/etc/iproute2/rt_tables"):
            with open("/etc/iproute2/rt_tables", 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        table_id = int(parts[0])
                        table_name = parts[1]
                        
                        if min_table_id <= table_id <= max_table_id:
                            # Extract VPN name from table name (if follows our pattern)
                            if table_name.endswith("_tbl"):
                                vpn_name = table_name[:-4]  # Remove "_tbl" suffix
                                if vpn_name not in active_vpns:
                                    print_colored(YELLOW, f"Found orphaned routing table: {table_id} ({table_name})")
                                    orphaned_tables.append({
                                        "id": table_id,
                                        "name": table_name,
                                        "vpn_name": vpn_name
                                    })
        
        # Check for tables that might not be in the rt_tables file
        ip_rule_output = subprocess.run(["ip", "rule", "show"], 
                                    capture_output=True, text=True).stdout
                                    
        for line in ip_rule_output.splitlines():
            match = re.search(r'lookup (\d+)', line)
            if match:
                table_id = int(match.group(1))
                if min_table_id <= table_id <= max_table_id:
                    vpn_found = False
                    for vpn_name in active_vpns:
                        # Check if table is referenced in active VPNs
                        if f"_{vpn_name}" in line or f"{vpn_name}_" in line:
                            vpn_found = True
                            break
                    
                    if not vpn_found and not any(t["id"] == table_id for t in orphaned_tables):
                        print_colored(YELLOW, f"Found orphaned routing rule for table: {table_id}")
                        orphaned_tables.append({
                            "id": table_id,
                            "name": f"unknown_{table_id}",
                            "vpn_name": "unknown"
                        })
        
    except Exception as e:
        print_colored(RED, f"Error checking routing tables: {e}")
    
    return orphaned_tables

def check_veth_interfaces(active_vpns):
    """Check for orphaned veth interfaces"""
    print_colored(GREEN, "Checking veth interfaces...")
    orphaned_veths = []
    
    try:
        ip_link_output = subprocess.run(["ip", "link", "show"], 
                                      capture_output=True, text=True).stdout
                                      
        for line in ip_link_output.splitlines():
            if "veth-" in line:
                match = re.search(r'\d+: (veth-\w+)[@:]', line)
                if match:
                    veth_name = match.group(1)
                    vpn_name = veth_name[5:]  # Remove "veth-" prefix
                    
                    if vpn_name not in active_vpns:
                        print_colored(YELLOW, f"Found orphaned veth interface: {veth_name}")
                        orphaned_veths.append({
                            "name": veth_name,
                            "vpn_name": vpn_name
                        })
    
    except Exception as e:
        print_colored(RED, f"Error checking veth interfaces: {e}")
    
    return orphaned_veths

def check_network_files(active_vpns):
    """Check for orphaned network configuration files"""
    print_colored(GREEN, "Checking network configuration files...")
    orphaned_files = []
    
    try:
        if NETWORKD_PATH.exists():
            for file_path in NETWORKD_PATH.glob("*.network"):
                file_name = file_path.name
                if file_name.startswith("vpn-"):
                    # Extract VPN name
                    vpn_name = file_name[4:].split('.')[0]  # Remove "vpn-" prefix and extension
                    
                    if vpn_name not in active_vpns:
                        print_colored(YELLOW, f"Found orphaned network file: {file_name}")
                        orphaned_files.append({
                            "path": str(file_path),
                            "name": file_name,
                            "vpn_name": vpn_name
                        })
    
    except Exception as e:
        print_colored(RED, f"Error checking network files: {e}")
    
    return orphaned_files

def cleanup_resources(orphaned_namespaces, orphaned_tables, orphaned_veths, orphaned_files, dry_run=True):
    """Clean up orphaned resources"""
    if dry_run:
        print_colored(YELLOW, "DRY RUN MODE - No changes will be made")
    
    # Count total resources to clean up
    total = len(orphaned_namespaces) + len(orphaned_tables) + len(orphaned_veths) + len(orphaned_files)
    if total == 0:
        print_colored(GREEN, "No orphaned resources found to clean up")
        return
        
    print_colored(GREEN, f"Preparing to clean up {total} orphaned resources")
    
    # Clean up network namespaces
    for ns in orphaned_namespaces:
        cmd = ["ip", "netns", "delete", ns["name"]]
        print_colored(YELLOW, f"{'Would execute' if dry_run else 'Executing'}: {' '.join(cmd)}")
        if not dry_run:
            try:
                subprocess.run(cmd, check=True)
                print_colored(GREEN, f"Successfully removed namespace: {ns['name']}")
            except subprocess.CalledProcessError as e:
                print_colored(RED, f"Failed to remove namespace {ns['name']}: {e}")
    
    # Clean up routing tables (rules)
    for table in orphaned_tables:
        # Get rules for this table
        try:
            rules_output = subprocess.run(["ip", "rule", "show", "table", str(table["id"])], 
                                      capture_output=True, text=True).stdout
                                      
            for line in rules_output.splitlines():
                if f"lookup {table['id']}" in line:
                    # Extract rule priority and selector
                    match = re.search(r'^(\d+):\s+(.+)\s+lookup\s+\d+', line)
                    if match:
                        priority = match.group(1)
                        selector = match.group(2).strip()
                        
                        cmd = ["ip", "rule", "del", "prio", priority]
                        if selector != "from all":
                            cmd.extend(selector.split())
                            
                        print_colored(YELLOW, f"{'Would execute' if dry_run else 'Executing'}: {' '.join(cmd)}")
                        if not dry_run:
                            try:
                                subprocess.run(cmd, check=True)
                                print_colored(GREEN, f"Successfully removed rule for table: {table['id']}")
                            except subprocess.CalledProcessError as e:
                                print_colored(RED, f"Failed to remove rule for table {table['id']}: {e}")
        
        except Exception as e:
            print_colored(RED, f"Error getting rules for table {table['id']}: {e}")
    
    # Clean up veth interfaces
    for veth in orphaned_veths:
        cmd = ["ip", "link", "delete", veth["name"]]
        print_colored(YELLOW, f"{'Would execute' if dry_run else 'Executing'}: {' '.join(cmd)}")
        if not dry_run:
            try:
                subprocess.run(cmd, check=True)
                print_colored(GREEN, f"Successfully removed veth interface: {veth['name']}")
            except subprocess.CalledProcessError as e:
                print_colored(RED, f"Failed to remove veth interface {veth['name']}: {e}")
    
    # Clean up network files
    for file in orphaned_files:
        print_colored(YELLOW, f"{'Would remove' if dry_run else 'Removing'} network file: {file['path']}")
        if not dry_run:
            try:
                os.remove(file['path'])
                print_colored(GREEN, f"Successfully removed network file: {file['name']}")
            except OSError as e:
                print_colored(RED, f"Failed to remove network file {file['name']}: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Check for orphaned VPN router resources")
    parser.add_argument("--clean", action="store_true", help="Clean up orphaned resources")
    parser.add_argument("--force", action="store_true", help="Don't ask for confirmation when cleaning")
    args = parser.parse_args()
    
    # Load configuration ranges
    min_table_id, max_table_id, network_prefix = load_config_ranges()
    print_colored(GREEN, f"Using resource ranges: Tables {min_table_id}-{max_table_id}, Network {network_prefix}.*.*")
    
    # Get active VPNs
    active_vpns = get_active_vpns()
    print_colored(GREEN, f"Found {len(active_vpns)} active VPNs: {', '.join(active_vpns) if active_vpns else 'none'}")
    
    # Check for orphaned resources
    orphaned_namespaces = check_network_namespaces(active_vpns)
    orphaned_tables = check_routing_tables(active_vpns, min_table_id, max_table_id)
    orphaned_veths = check_veth_interfaces(active_vpns)
    orphaned_files = check_network_files(active_vpns)
    
    # Summary
    total_orphaned = len(orphaned_namespaces) + len(orphaned_tables) + len(orphaned_veths) + len(orphaned_files)
    print_colored(GREEN, f"\nOrphaned resource summary:")
    print_colored(GREEN, f"- Network namespaces: {len(orphaned_namespaces)}")
    print_colored(GREEN, f"- Routing tables: {len(orphaned_tables)}")
    print_colored(GREEN, f"- Veth interfaces: {len(orphaned_veths)}")
    print_colored(GREEN, f"- Network files: {len(orphaned_files)}")
    
    # Clean up if requested
    if args.clean and total_orphaned > 0:
        if args.force:
            print_colored(YELLOW, "Automatic cleanup requested with --force")
            cleanup_resources(orphaned_namespaces, orphaned_tables, orphaned_veths, orphaned_files, dry_run=False)
        else:
            print_colored(YELLOW, "")
            answer = input("Clean up these orphaned resources? (y/N): ").strip().lower()
            if answer == 'y':
                cleanup_resources(orphaned_namespaces, orphaned_tables, orphaned_veths, orphaned_files, dry_run=False)
            else:
                print_colored(YELLOW, "Cleanup cancelled")
    elif args.clean:
        print_colored(GREEN, "No orphaned resources to clean up")
    else:
        if total_orphaned > 0:
            print_colored(YELLOW, "Run with --clean to clean up these resources")

if __name__ == "__main__":
    main()
