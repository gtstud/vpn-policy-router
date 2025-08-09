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
        
    if not orphaned_ns:
        print_colored(GREEN, "No orphaned namespaces found")
        
    return orphaned_ns


def check_network_interfaces(active_vpns, network_prefix):
    """Check for orphaned network interfaces"""
    print_colored(GREEN, "Checking network interfaces...")
    orphaned_interfaces = []
    
    try:
        # Check by name pattern
        if_output = subprocess.run(["ip", "link", "show"], 
                                  capture_output=True, text=True).stdout
        
        if_pattern = re.compile(r"\d+:\s+(v-([a-zA-Z0-9_-]+)-[wvp])[@:]")
        
        for line in if_output.splitlines():
            match = if_pattern.search(line)
            if match:
                if_name = match.group(1)
                vpn_name = match.group(2)
                
                # Check if VPN is active
                if vpn_name not in active_vpns:
                    print_colored(YELLOW, f"Found orphaned interface by name: {if_name}")
                    orphaned_interfaces.append({
                        "name": if_name,
                        "vpn_name": vpn_name,
                        "detection_method": "name_pattern"
                    })
        
        # Check by IP range
        addr_output = subprocess.run(["ip", "addr", "show"], 
                                   capture_output=True, text=True).stdout
        
        ip_pattern = re.compile(rf"inet ({network_prefix}\.\d+\.\d+)/\d+.+\s(\S+)$", re.MULTILINE)
        
        for match in ip_pattern.finditer(addr_output):
            ip_addr = match.group(1)
            if_name = match.group(2)
            
            # Skip interfaces already found by name pattern
            if any(iface["name"] == if_name for iface in orphaned_interfaces):
                continue
            
            # Skip interfaces that match our naming pattern but are in active VPNs
            if_pattern = re.compile(r"v-([a-zA-Z0-9_-]+)-[wvp]")
            name_match = if_pattern.match(if_name)
            if name_match:
                vpn_name = name_match.group(1)
                if vpn_name in active_vpns:
                    continue
            
            print_colored(YELLOW, f"Found interface with IP in our range: {if_name} ({ip_addr})")
            orphaned_interfaces.append({
                "name": if_name,
                "ip": ip_addr,
                "detection_method": "ip_range"
            })
            
    except Exception as e:
        print_colored(RED, f"Error checking network interfaces: {e}")
        
    if not orphaned_interfaces:
        print_colored(GREEN, "No orphaned interfaces found")
        
    return orphaned_interfaces


def check_routing_tables(active_vpns, min_table_id, max_table_id):
    """Check for orphaned routing tables"""
    print_colored(GREEN, "Checking routing tables...")
    orphaned_tables = []
    
    # Get all active table IDs
    active_table_ids = set()
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                config = json.load(f)
                
            active_table_ids = {int(vpn["routing_table_id"]) for vpn in config.get("vpn_connections", [])
                               if "routing_table_id" in vpn and vpn["routing_table_id"].isdigit()}
        except Exception as e:
            print_colored(RED, f"Error loading VPN definitions: {e}")
    
    # Check routing table files
    try:
        # Check rt_tables.d first
        rt_tables_d_path = Path("/etc/iproute2/rt_tables.d")
        if rt_tables_d_path.exists():
            for file_path in rt_tables_d_path.glob("*.conf"):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Extract table ID
                    match = re.match(r"^\s*(\d+)\s+(\S+)", content)
                    if match:
                        table_id = int(match.group(1))
                        table_name = match.group(2)
                        
                        if (min_table_id <= table_id <= max_table_id and 
                            table_id not in active_table_ids):
                            
                            # Extract VPN name from file name if possible
                            file_name = file_path.name
                            vpn_name = None
                            if "_" in file_name:
                                vpn_name = file_name.split("_")[0]
                                
                            print_colored(YELLOW, f"Found orphaned routing table: {table_id} ({table_name}) in {file_path}")
                            orphaned_tables.append({
                                "id": table_id,
                                "name": table_name,
                                "path": str(file_path),
                                "vpn_name": vpn_name
                            })
                except Exception as e:
                    print_colored(RED, f"Error processing file {file_path}: {e}")
        
        # Check main rt_tables file
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        if rt_tables_path.exists():
            try:
                with open(rt_tables_path, 'r') as f:
                    content = f.read()
                    
                for line in content.splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        # Extract table ID and name
                        match = re.match(r"^\s*(\d+)\s+(\S+)", line)
                        if match:
                            table_id = int(match.group(1))
                            table_name = match.group(2)
                            
                            if (min_table_id <= table_id <= max_table_id and 
                                table_id not in active_table_ids and
                                not any(table["id"] == table_id for table in orphaned_tables)):
                                
                                print_colored(YELLOW, f"Found orphaned routing table in main rt_tables: {table_id} ({table_name})")
                                orphaned_tables.append({
                                    "id": table_id,
                                    "name": table_name,
                                    "path": str(rt_tables_path),
                                    "vpn_name": None
                                })
            except Exception as e:
                print_colored(RED, f"Error processing main rt_tables file: {e}")
                
    except Exception as e:
        print_colored(RED, f"Error checking routing tables: {e}")
        
    if not orphaned_tables:
        print_colored(GREEN, "No orphaned routing tables found")
        
    return orphaned_tables


def check_routing_rules(active_vpns, min_table_id, max_table_id):
    """Check for orphaned routing rules"""
    print_colored(GREEN, "Checking routing rules...")
    orphaned_rules = []
    
    # Get all active table IDs
    active_table_ids = set()
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                config = json.load(f)
                
            active_table_ids = {int(vpn["routing_table_id"]) for vpn in config.get("vpn_connections", [])
                               if "routing_table_id" in vpn and vpn["routing_table_id"].isdigit()}
        except Exception as e:
            print_colored(RED, f"Error loading VPN definitions: {e}")
    
    # Check IP rules
    try:
        rules_output = subprocess.run(["ip", "rule", "list"], 
                                     capture_output=True, text=True).stdout
        
        for line in rules_output.splitlines():
            if "lookup" in line:
                parts = line.split("lookup")
                if len(parts) >= 2:
                    table_ref = parts[1].strip()
                    
                    if table_ref.isdigit():
                        table_id = int(table_ref)
                        
                        if (min_table_id <= table_id <= max_table_id and 
                            table_id not in active_table_ids):
                            
                            # Extract from clause if exists
                            from_match = re.search(r"from\s+([0-9./]+)", line)
                            from_ip = from_match.group(1) if from_match else None
                            
                            # Extract priority
                            priority_match = re.search(r"^(\d+):", line)
                            priority = priority_match.group(1) if priority_match else None
                            
                            print_colored(YELLOW, f"Found orphaned routing rule: {line}")
                            orphaned_rules.append({
                                "rule": line,
                                "table_id": table_id,
                                "from_ip": from_ip,
                                "priority": priority
                            })
    except Exception as e:
        print_colored(RED, f"Error checking routing rules: {e}")
        
    if not orphaned_rules:
        print_colored(GREEN, "No orphaned routing rules found")
        
    return orphaned_rules


def check_systemd_files(active_vpns):
    """Check for orphaned systemd files"""
    print_colored(GREEN, "Checking systemd files...")
    orphaned_files = []
    
    # Check service files
    try:
        for service_path in Path("/etc/systemd/system").glob("vpn-ns-*.service"):
            vpn_name = service_path.name.split("vpn-ns-")[1].split(".")[0]
            
            if vpn_name not in active_vpns:
                print_colored(YELLOW, f"Found orphaned service file: {service_path}")
                orphaned_files.append({
                    "type": "service",
                    "path": str(service_path),
                    "vpn_name": vpn_name
                })
    except Exception as e:
        print_colored(RED, f"Error checking service files: {e}")
    
    # Check networkd files
    try:
        patterns = ["10-v-*-*.netdev", "10-v-*-*.network", "20-v-*-*.netdev", "20-v-*-*.network", "50-*-client-*.network"]
        
        for pattern in patterns:
            for file_path in NETWORKD_PATH.glob(pattern):
                # Extract VPN name
                if "-v-" in file_path.name:
                    # Format v-{vpn_name}-* for veth and wireguard devices
                    name_parts = file_path.name.split("-v-")
                    if len(name_parts) > 1:
                        vpn_parts = name_parts[1].split("-", 1)
                        if len(vpn_parts) > 1:
                            vpn_name = vpn_parts[0]
                            
                            if vpn_name not in active_vpns:
                                print_colored(YELLOW, f"Found orphaned networkd file: {file_path}")
                                orphaned_files.append({
                                    "type": "networkd",
                                    "path": str(file_path),
                                    "vpn_name": vpn_name
                                })
                elif "client-" in file_path.name:
                    # Format 50-{vpn_name}-client-*
                    name_parts = file_path.name.split("-client-")
                    if len(name_parts) > 1:
                        vpn_parts = name_parts[0].split("-", 1)
                        if len(vpn_parts) > 1:
                            vpn_name = vpn_parts[1]
                            
                            if vpn_name not in active_vpns:
                                print_colored(YELLOW, f"Found orphaned client rule file: {file_path}")
                                orphaned_files.append({
                                    "type": "networkd_rule",
                                    "path": str(file_path),
                                    "vpn_name": vpn_name
                                })
    except Exception as e:
        print_colored(RED, f"Error checking networkd files: {e}")
    
    if not orphaned_files:
        print_colored(GREEN, "No orphaned systemd files found")
        
    return orphaned_files


def print_summary(all_orphaned_resources):
    """Print a summary of all orphaned resources"""
    print("\n" + "="*60)
    print_colored(GREEN, "ORPHANED RESOURCES SUMMARY:")
    
    total_resources = sum(len(resources) for resources in all_orphaned_resources.values())
    
    if total_resources == 0:
        print_colored(GREEN, "No orphaned resources found. System is clean.")
        return
    
    print_colored(YELLOW, f"Found {total_resources} total orphaned resources:")
    
    for resource_type, resources in all_orphaned_resources.items():
        if resources:
            print_colored(YELLOW, f"- {resource_type}: {len(resources)}")
            
    print("\nTo clean up these resources, run:")
    print_colored(GREEN, "  sudo /usr/local/bin/vpn-apply.py --clean-orphaned")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VPN Router Resource Check Script")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print_colored(RED, "This script must be run as root")
        sys.exit(1)
        
    # Load configuration ranges
    min_table_id, max_table_id, network_prefix = load_config_ranges()
    
    # Get active VPNs
    active_vpns = get_active_vpns()
    
    print_colored(GREEN, f"Using routing table ID range: {min_table_id}-{max_table_id}")
    print_colored(GREEN, f"Using network prefix: {network_prefix}")
    print_colored(GREEN, f"Found {len(active_vpns)} active VPNs: {', '.join(active_vpns) if active_vpns else 'none'}")
    print("")
    
    # Check for orphaned resources
    orphaned_namespaces = check_network_namespaces(active_vpns)
    print("")
    
    orphaned_interfaces = check_network_interfaces(active_vpns, network_prefix)
    print("")
    
    orphaned_tables = check_routing_tables(active_vpns, min_table_id, max_table_id)
    print("")
    
    orphaned_rules = check_routing_rules(active_vpns, min_table_id, max_table_id)
    print("")
    
    orphaned_files = check_systemd_files(active_vpns)
    print("")
    
    # Organize results
    all_orphaned_resources = {
        "network_namespaces": orphaned_namespaces,
        "network_interfaces": orphaned_interfaces,
        "routing_tables": orphaned_tables,
        "routing_rules": orphaned_rules,
        "systemd_files": orphaned_files
    }
    
    if args.json:
        # Output as JSON
        print(json.dumps(all_orphaned_resources, indent=2))
    else:
        # Print summary
        print_summary(all_orphaned_resources)
    

if __name__ == "__main__":
    main()