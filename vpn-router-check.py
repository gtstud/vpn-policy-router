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

def get_vpn_config():
    """Load and return the VPN configuration."""
    if VPN_DEFINITIONS_PATH.exists():
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                return json.load(f)
        except Exception as e:
            print_colored(RED, f"Error loading VPN definitions: {e}")
    return None

def check_system_resources(defined_vpns, vpn_config):
    """Check for orphaned system resources (interfaces, namespaces, files, firewalld)."""
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

    # Check for orphaned interfaces in firewalld zone
    firewalld_config = vpn_config.get('system_config', {}).get('firewalld', {})
    vpn_zone = firewalld_config.get('zone_vpn')
    if vpn_zone:
        try:
            result = subprocess.run(["firewall-cmd", "--zone", vpn_zone, "--list-interfaces"], capture_output=True, text=True, check=True)
            interfaces_in_zone = result.stdout.strip().split()
            for if_name in interfaces_in_zone:
                match = re.search(r'v-([a-zA-Z0-9_-]+)-v', if_name)
                if match:
                    vpn_name = match.group(1)
                    if vpn_name not in defined_vpns:
                        print_colored(YELLOW, f"Found orphaned interface in firewalld zone '{vpn_zone}': {if_name}")
                        orphaned.append({"name": if_name, "type": "firewalld_interface", "zone": vpn_zone})
        except FileNotFoundError:
            print_colored(RED, "firewall-cmd not found. Skipping firewalld check.")
        except subprocess.CalledProcessError as e:
            print_colored(RED, f"Error checking firewalld zone '{vpn_zone}': {e.stderr}")

    # Check for orphaned nftables rules
    nftables_config = vpn_config.get('system_config', {}).get('nftables', {})
    table = nftables_config.get('table')
    chain = nftables_config.get('chain')
    if table and chain:
        try:
            result = subprocess.run(["nft", "--handle", "list", "chain", table, chain], capture_output=True, text=True, check=True)
            rules = result.stdout.strip().split('\n')
            defined_veth_networks = {vpn['veth_network'] for vpn in vpn_config.get("vpn_connections", [])}

            for rule in rules:
                match = re.search(r'ip saddr (([0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', rule)
                if match:
                    rule_saddr = match.group(1)
                    if rule_saddr not in defined_veth_networks:
                        handle_match = re.search(r'handle\s+(\d+)', rule)
                        handle = handle_match.group(1) if handle_match else 'N/A'
                        print_colored(YELLOW, f"Found orphaned nftables rule with source {rule_saddr} (handle: {handle})")
                        orphaned.append({"name": rule, "type": "nftables_rule", "handle": handle, "table": table, "chain": chain})
        except FileNotFoundError:
            print_colored(RED, "nft not found. Skipping nftables check.")
        except subprocess.CalledProcessError as e:
            print_colored(RED, f"Error checking nftables chain '{table}/{chain}': {e.stderr}")

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
        elif res_type == "firewalld_interface":
            cmd = ["firewall-cmd", "--zone", resource['zone'], "--remove-interface", res_name, "--permanent"]
        elif res_type == "nftables_rule":
            if resource['handle'] != 'N/A':
                cmd = ["nft", "delete", "rule", resource['table'], resource['chain'], "handle", resource['handle']]
            else:
                print_colored(RED, f"  -> Cannot remove rule due to missing handle: {res_name}")

        if cmd:
            if not dry_run:
                try:
                    subprocess.run(cmd, check=True)
                    print_colored(GREEN, f"  -> Removed {res_type}: {res_name}")
                    if res_type == "firewalld_interface":
                        subprocess.run(["firewall-cmd", "--reload"], check=True)
                except Exception as e:
                    print_colored(RED, f"  -> Failed to remove {res_type}: {e}")
            else:
                print(f"  -> Would run: {' '.join(cmd)}")
                if res_type == "firewalld_interface":
                    print("  -> Would run: firewall-cmd --reload")

    print_colored(YELLOW, f"--- {mode} Complete ---")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Check for orphaned VPN router resources.")
    parser.add_argument("--clean", action="store_true", help="Clean up orphaned resources.")
    args = parser.parse_args()

    vpn_config = get_vpn_config()
    if not vpn_config:
        sys.exit(1)

    defined_vpns = [vpn["name"] for vpn in vpn_config.get("vpn_connections", [])]
    print_colored(GREEN, f"Found {len(defined_vpns)} defined VPNs: {', '.join(defined_vpns) if defined_vpns else 'none'}")
    print("-" * 30)

    orphaned_resources = check_system_resources(defined_vpns, vpn_config)
    
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
