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
                               if "routing_table