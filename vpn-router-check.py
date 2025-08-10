#!/usr/bin/env python3
"""
VPN Router Resource Check Script
This script checks for orphaned VPN router resources based on the new implementation.
"""

import os
import re
import sys
import json
import argparse
import subprocess
from pathlib import Path

# ANSI colors for output
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
RED = '\033[0;31m'
NC = '\033[0m'  # No Color

# Base directories
CONFIG_DIR = Path("/etc/vpn-router")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
NETWORKD_DIR = Path("/etc/systemd/network")
SYSTEMD_DIR = Path("/etc/systemd/system")

def print_colored(color, message):
    """Print colored message"""
    print(f"{color}{message}{NC}")

def get_defined_vpns():
    """Get list of all defined VPN names from configuration"""
    defined_vpns = []
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                config = json.load(f)
            defined_vpns = [vpn["name"] for vpn in config.get("vpn_connections", [])]
        except Exception as e:
            print_colored(RED, f"Error loading VPN definitions: {e}")
    return defined_vpns

def check_system_resources(defined_vpns):
    """Check for orphaned system resources (interfaces, namespaces, files)."""
    print_colored(GREEN, "Checking system resources...")
    orphaned = []
    
    # Check for orphaned interfaces (veth and wg)
    try:
        ip_link_output = subprocess.run(["ip", "link", "show"], capture_output=True, text=True).stdout
        for line in ip_link_output.splitlines():
            match = re.search(r'\d+: v-([a-zA-Z0-9_-]+)-[vpw]', line)
            if match:
                vpn_name = match.group(1)
                if vpn_name not in defined_vpns:
                    if_name = match.group(0).split(':')[1].strip().split('@')[0]
                    print_colored(YELLOW, f"Found orphaned interface: {if_name}")
                    orphaned.append({"name": if_name, "type": "interface"})
    except Exception as e:
        print_colored(RED, f"Error checking interfaces: {e}")

    # Check for orphaned namespaces
    try:
        ns_output = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
        for line in ns_output.splitlines():
            match = re.search(r'ns-([a-zA-Z0-9_-]+)', line)
            if match:
                vpn_name = match.group(1)
                if vpn_name not in defined_vpns:
                    ns_name = match.group(0)
                    print_colored(YELLOW, f"Found orphaned namespace: {ns_name}")
                    orphaned.append({"name": ns_name, "type": "namespace"})
    except Exception as e:
        print_colored(RED, f"Error checking namespaces: {e}")
        
    # Check for orphaned files
    all_files = list(SYSTEMD_DIR.glob("vpn-ns-*.service")) + \
                list(NETWORKD_DIR.glob("10-v-*-v.netdev")) + \
                list(NETWORKD_DIR.glob("10-v-*-v.network")) + \
                list(NETWORKD_DIR.glob("20-v-*-w.netdev")) + \
                list(NETWORKD_DIR.glob("30-v-*-p.network")) + \
                list(NETWORKD_DIR.glob("30-v-*-w.network"))
    
    for f in all_files:
        match = re.search(r'v-([a-zA-Z0-9_-]+)-', f.name) or re.search(r'ns-([a-zA-Z0-9_-]+)', f.name)
        if match:
            vpn_name = match.group(1)
            if vpn_name not in defined_vpns:
                print_colored(YELLOW, f"Found orphaned file: {f}")
                orphaned.append({"name": str(f), "type": "file"})
                
    return orphaned

def cleanup_resources(orphaned_resources, dry_run=True):
    """Clean up orphaned resources."""
    if not orphaned_resources:
        print_colored(GREEN, "No orphaned resources to clean up.")
        return
        
    mode = "DRY RUN" if dry_run else "CLEANUP"
    print_colored(YELLOW, f"--- Starting {mode} ---")

    for resource in orphaned_resources:
        res_type = resource["type"]
        res_name = resource["name"]
        print(f"Resource: {res_type.capitalize()} ({res_name})")
        
        cmd = None
        if res_type == "file":
            cmd = ["rm", "-f", res_name]
        elif res_type == "interface":
            cmd = ["ip", "link", "delete", res_name]
        elif res_type == "namespace":
            cmd = ["ip", "netns", "delete", res_name]

        if cmd:
            if not dry_run:
                try:
                    subprocess.run(cmd, check=True)
                    print_colored(GREEN, f"  -> Removed {res_type}: {res_name}")
                except Exception as e:
                    print_colored(RED, f"  -> Failed to remove {res_type}: {e}")
            else:
                print(f"  -> Would run: {' '.join(cmd)}")
    print_colored(YELLOW, f"--- {mode} Complete ---")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Check for orphaned VPN router resources.")
    parser.add_argument("--clean", action="store_true", help="Clean up orphaned resources.")
    args = parser.parse_args()

    defined_vpns = get_defined_vpns()
    print_colored(GREEN, f"Found {len(defined_vpns)} defined VPNs: {', '.join(defined_vpns) if defined_vpns else 'none'}")
    print("-" * 30)

    orphaned_resources = check_system_resources(defined_vpns)
    
    print("-" * 30)
    if not orphaned_resources:
        print_colored(GREEN, "✓ No orphaned resources found.")
    else:
        print_colored(YELLOW, f"Found {len(orphaned_resources)} orphaned resources.")
        if args.clean:
            cleanup_resources(orphaned_resources, dry_run=False)
        else:
            print_colored(YELLOW, "Run with --clean to remove them.")

if __name__ == "__main__":
    main()
