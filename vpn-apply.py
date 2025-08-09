#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VPN Router State Enforcement Script
-----------------------------------
This script applies the VPN configuration based on the JSON configuration files.
Version: 1.0 (nftables)
Date: 2025-08-09
"""

import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import grp
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any

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
NETWORKD_PATH = Path("/etc/systemd/network")
FIREWALLD_PATH = Path("/etc/firewalld")
MAX_NETDEV_NAME_LENGTH = 15  # Linux kernel's IFNAMSIZ limit is 16, but needs null terminator

class VpnRouter:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.vpn_definitions = {}
        self.client_assignments = {}
        self.resolved_assignments = []
        self.changed_files_by_type = {
            "networkd": False,
            "service": False,
            "routing": False
        }
        self.changed_vpn_configs = set()
        
    def load_configuration(self) -> bool:
        """Load and validate configuration files"""
        try:
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                self.vpn_definitions = json.load(f)
                
            with open(VPN_CLIENTS_PATH, 'r') as f:
                self.client_assignments = json.load(f)
                
            return True
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            return False
        except FileNotFoundError as e:
            logger.error(f"Configuration file not found: {e}")
            return False
    
    def validate_configuration(self) -> bool:
        """Validate the configuration"""
        # 1. Check schema structure
        if "vpn_connections" not in self.vpn_definitions:
            logger.error("Missing 'vpn_connections' key in vpn-definitions.json")
            return False
            
        if "assignments" not in self.client_assignments:
            logger.error("Missing 'assignments' key in vpn-clients.json")
            return False
            
        # 2. Validate VPN definitions
        vpn_names = set()
        routing_table_ids = set()
        routing_table_names = set()
        veth_networks = set()
        
        for vpn in self.vpn_definitions["vpn_connections"]:
            # Check required fields
            required_fields = [
                "name", "client_private_key", "peer_public_key", 
                "peer_endpoint", "vpn_assigned_ip", "veth_network",
                "routing_table_id", "routing_table_name", "router_lan_interface"
            ]
            
            for field in required_fields:
                if field not in vpn:
                    logger.error(f"VPN definition missing required field: {field}")
                    return False
            
            # Check uniqueness constraints
            if vpn["name"] in vpn_names:
                logger.error(f"Duplicate VPN name: {vpn['name']}")
                return False
            vpn_names.add(vpn["name"])
            
            if vpn["routing_table_id"] in routing_table_ids:
                logger.error(f"Duplicate routing table ID: {vpn['routing_table_id']}")
                return False
            routing_table_ids.add(vpn["routing_table_id"])
            
            if vpn["routing_table_name"] in routing_table_names:
                logger.error(f"Duplicate routing table name: {vpn['routing_table_name']}")
                return False
            routing_table_names.add(vpn["routing_table_name"])
            
            if vpn["veth_network"] in veth_networks:
                logger.error(f"Duplicate veth network: {vpn['veth_network']}")
                return False
            veth_networks.add(vpn["veth_network"])
            
            # Validate veth_network is a /30
            try:
                network, prefix = vpn["veth_network"].split('/')
                if int(prefix) != 30:
                    logger.error(f"veth_network must be a /30 CIDR, got {vpn['veth_network']}")
                    return False
            except ValueError:
                logger.error(f"Invalid veth_network format: {vpn['veth_network']}")
                return False
                
            # Calculate and validate interface names
            vpn_name = vpn["name"]
            wg_if_name = f"v-{vpn_name}-w"
            veth_if_name = f"v-{vpn_name}-v"
            veth_peer_name = f"v-{vpn_name}-p"
            
            # Validate interface name lengths
            if len(wg_if_name) > MAX_NETDEV_NAME_LENGTH:
                logger.error(f"WireGuard interface name '{wg_if_name}' exceeds maximum length of {MAX_NETDEV_NAME_LENGTH}")
                return False
            
            if len(veth_if_name) > MAX_NETDEV_NAME_LENGTH:
                logger.error(f"Veth interface name '{veth_if_name}' exceeds maximum length of {MAX_NETDEV_NAME_LENGTH}")
                return False
                
            if len(veth_peer_name) > MAX_NETDEV_NAME_LENGTH:
                logger.error(f"Veth peer interface name '{veth_peer_name}' exceeds maximum length of {MAX_NETDEV_NAME_LENGTH}")
                return False
        
        # 3. Validate client assignments
        client_names = set()
        
        for client in self.client_assignments["assignments"]:
            # Check required fields
            if "display_name" not in client:
                logger.error("Client assignment missing required field: display_name")
                return False
                
            # Check uniqueness constraints
            if client["display_name"] in client_names:
                logger.error(f"Duplicate client display name: {client['display_name']}")
                return False
            client_names.add(client["display_name"])
            
            # Check mutual exclusivity of hostname and ip_address
            if (client.get("hostname") is None and client.get("ip_address") is None) or \
               (client.get("hostname") is not None and client.get("ip_address") is not None):
                logger.error(f"Client {client['display_name']} must have exactly one of 'hostname' or 'ip_address'")
                return False
                
            # Check assigned_vpn exists
            if client.get("assigned_vpn") is not None and client["assigned_vpn"] not in vpn_names:
                logger.error(f"Client {client['display_name']} assigned to non-existent VPN: {client['assigned_vpn']}")
                return False
        
        logger.info("Configuration validation successful")
        return True
    
    def prune_expired_clients(self) -> None:
        """Remove expired client assignments"""
        now = datetime.now(timezone.utc).isoformat()
        active_assignments = []
        
        for client in self.client_assignments["assignments"]:
            expiry = client.get("assignment_expiry")
            if expiry is None or expiry > now:
                active_assignments.append(client)
            else:
                logger.info(f"Pruning expired assignment for {client['display_name']}")
        
        self.client_assignments["assignments"] = active_assignments
        
        # Save pruned assignments if not in dry run mode
        if not self.dry_run:
            with open(VPN_CLIENTS_PATH, 'w') as f:
                json.dump(self.client_assignments, f, indent=2)
                
    def resolve_hostname_assignments(self) -> None:
        """Resolve hostnames to IP addresses for client assignments"""
        self.resolved_assignments = []
        
        for client in self.client_assignments["assignments"]:
            resolved_client = client.copy()
            
            # If client has a hostname, attempt to resolve it
            if client.get("hostname"):
                try:
                    resolved_ip = socket.gethostbyname(client["hostname"])
                    resolved_client["resolved_ip"] = resolved_ip
                    logger.info(f"Resolved {client['hostname']} to {resolved_ip}")
                    self.resolved_assignments.append(resolved_client)
                except socket.gaierror:
                    logger.warning(f"Could not resolve hostname {client['hostname']} for {client['display_name']}")
                    # Skip this client for now
                    continue
            else:
                # Client has a static IP, no resolution needed
                resolved_client["resolved_ip"] = client["ip_address"]
                self.resolved_assignments.append(resolved_client)
    
    def generate_networkd_files(self) -> Dict[str, str]:
        """Generate systemd-networkd configuration files"""
        generated_files = {}
        
        for vpn in self.vpn_definitions["vpn_connections"]:
            vpn_name = vpn["name"]
            wg_if_name = f"v-{vpn_name}-w"
            veth_if_name = f"v-{vpn_name}-v"
            veth_peer_name = f"v-{vpn_name}-p"
            
            # Generate netdev file for the WireGuard interface
            wg_netdev = f"""# VPN Router Interface Definition
# Interface naming convention: v-{{vpn_name}}-{{suffix}}
# where suffix: w=WireGuard, v=veth, p=peer

[NetDev]
Name={wg_if_name}
Kind=wireguard
Description=WireGuard VPN interface for {vpn.get('description', vpn_name)}

[WireGuard]
PrivateKey={vpn["client_private_key"]}
ListenPort=51820

[WireGuardPeer]
PublicKey={vpn["peer_public_key"]}
Endpoint={vpn["peer_endpoint"]}
AllowedIPs=0.0.0.0/0, ::/0
PersistentKeepalive=25
"""
            generated_files[f"{NETWORKD_PATH}/10-{wg_if_name}.netdev"] = wg_netdev
            
            # Generate network file for the WireGuard interface
            wg_network = f"""# VPN Router Network Configuration
# Interface naming convention: v-{{vpn_name}}-{{suffix}}
# where suffix: w=WireGuard, v=veth, p=peer

[Match]
Name={wg_if_name}

[Network]
Address={vpn["vpn_assigned_ip"]}
"""
            generated_files[f"{NETWORKD_PATH}/10-{wg_if_name}.network"] = wg_network
            
            # Generate veth pair for the network namespace
            veth_netdev = f"""# VPN Router Interface Definition
# Interface naming convention: v-{{vpn_name}}-{{suffix}}
# where suffix: w=WireGuard, v=veth, p=peer

[NetDev]
Name={veth_if_name}
Kind=veth

[Peer]
Name={veth_peer_name}
"""
            generated_files[f"{NETWORKD_PATH}/20-{veth_if_name}.netdev"] = veth_netdev
            
            # Calculate IPs for veth pair
            network_parts = vpn["veth_network"].split('/')
            network_base = network_parts[0].split('.')
            router_ip = f"{network_base[0]}.{network_base[1]}.{network_base[2]}.{int(network_base[3]) + 1}"
            ns_ip = f"{network_base[0]}.{network_base[1]}.{network_base[2]}.{int(network_base[3]) + 2}"
            
            # Generate network file for router end of veth
            veth_network = f"""# VPN Router Network Configuration
# Interface naming convention: v-{{vpn_name}}-{{suffix}}
# where suffix: w=WireGuard, v=veth, p=peer

[Match]
Name={veth_if_name}

[Network]
Address={router_ip}/30
ConfigureWithoutCarrier=yes
"""
            generated_files[f"{NETWORKD_PATH}/20-{veth_if_name}.network"] = veth_network
            
            # Generate routing table definition in /etc/iproute2/rt_tables.d/
            rt_table = f"{vpn['routing_table_id']}\t{vpn['routing_table_name']}\n"
            generated_files[f"/etc/iproute2/rt_tables.d/{vpn_name}.conf"] = rt_table
            
            # Generate a systemd unit file for setting up the network namespace
            # Using a different approach to minimize disruption
            ns_setup = f"""# Network namespace service for VPN routing
# Part of the Declarative Policy-Based VPN Router system
# Manages network namespace, veth peer, and NAT for isolated routing

[Unit]
Description=VPN Network Namespace for {vpn_name}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Check if namespace exists first
ExecStartPre=/bin/bash -c 'if ! ip netns list | grep -q "^ns-{vpn_name} "; then ip netns add ns-{vpn_name}; fi'

# Setup network namespace only if needed - using ExecStartPre for checks
ExecStartPre=/bin/bash -c 'if ! ip netns exec ns-{vpn_name} ip link show {veth_peer_name} &>/dev/null; then exit 0; else exit 1; fi || true'
ExecStart=/bin/bash -c 'ip link set {veth_peer_name} netns ns-{vpn_name} || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} ip addr add {ns_ip}/30 dev {veth_peer_name} || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} ip link set {veth_peer_name} up || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} ip route replace default via {router_ip} || true'

# Setup NAT only if not already configured - check table existence first
ExecStartPre=/bin/bash -c 'if ! ip netns exec ns-{vpn_name} nft list tables | grep -q "table ip nat"; then exit 0; else exit 1; fi || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} nft add table nat || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} nft "add chain nat postrouting {{ type nat hook postrouting priority 100; policy accept; }}" || true'
ExecStart=/bin/bash -c 'ip netns exec ns-{vpn_name} nft add rule nat postrouting oifname {wg_if_name} masquerade || true'

# Do graceful cleanup on stop - only remove things if they exist
ExecStop=/bin/bash -c 'if ip netns exec ns-{vpn_name} nft list tables | grep -q "table ip nat"; then ip netns exec ns-{vpn_name} nft flush table nat; ip netns exec ns-{vpn_name} nft delete table nat; fi || true'
ExecStop=/bin/bash -c 'if ip netns list | grep -q "^ns-{vpn_name} "; then ip netns del ns-{vpn_name}; fi || true'

[Install]
WantedBy=multi-user.target
"""
            generated_files[f"/etc/systemd/system/vpn-ns-{vpn_name}.service"] = ns_setup
            
            # Generate policy routing rules for each client assigned to this VPN
            for client in self.resolved_assignments:
                if client.get("assigned_vpn") == vpn_name:
                    client_ip = client["resolved_ip"]
                    policy_rule = f"""# Policy routing rule for client: {client['display_name']}
# Routes traffic from this client through the {vpn_name} VPN

[RoutingPolicyRule]
From={client_ip}/32
Table={vpn["routing_table_name"]}
Priority=100
"""
                    policy_file = f"50-{vpn_name}-client-{client['display_name'].lower().replace(' ', '-')}.rules"
                    generated_files[f"{NETWORKD_PATH}/{policy_file}"] = policy_rule
        
        return generated_files

    def check_namespace_status(self, vpn_name: str) -> Dict[str, bool]:
        """Check if a namespace exists and is properly configured"""
        status = {
            "exists": False,
            "veth_configured": False,
            "routes_configured": False,
            "nat_configured": False
        }
        
        # Check if namespace exists
        cmd = ["ip", "netns", "list"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if f"ns-{vpn_name}" in result.stdout:
            status["exists"] = True
            
            # If namespace exists, check its configuration
            veth_if_name = f"v-{vpn_name}-p"
            wg_if_name = f"v-{vpn_name}-w"
            
            # Check if veth interface exists in namespace
            cmd = ["ip", "netns", "exec", f"ns-{vpn_name}", "ip", "link", "show", veth_if_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            status["veth_configured"] = result.returncode == 0
            
            # Check if default route exists
            cmd = ["ip", "netns", "exec", f"ns-{vpn_name}", "ip", "route", "show", "default"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            status["routes_configured"] = result.returncode == 0 and "default" in result.stdout
            
            # Check if NAT is configured
            cmd = ["ip", "netns", "exec", f"ns-{vpn_name}", "nft", "list", "table", "nat"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            status["nat_configured"] = result.returncode == 0 and "masquerade" in result.stdout and wg_if_name in result.stdout
            
        return status

    def write_file(self, path: str, content: str) -> Dict[str, bool]:
        """Write a file and track changes by file type"""
        result = {"changed": False, "error": False}
        path_obj = Path(path)
        
        # Create parent directories if they don't exist
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if the file exists and has the same content
        if path_obj.exists():
            try:
                with open(path_obj, 'r') as f:
                    current_content = f.read()
                if current_content == content:
                    logger.debug(f"File {path} is unchanged")
                    return result
            except Exception as e:
                logger.error(f"Error reading {path}: {e}")
                result["error"] = True
                return result
        
        # Write the new content
        try:
            logger.info(f"Writing {path}")
            with open(path_obj, 'w') as f:
                f.write(content)
            result["changed"] = True
            
            # Update change tracking based on file type
            if path.endswith('.netdev') or path.endswith('.network'):
                self.changed_files_by_type["networkd"] = True
                # Extract VPN name from file path for tracking changes
                for vpn in self.vpn_definitions["vpn_connections"]:
                    vpn_name = vpn["name"]
                    if f"-{vpn_name}-" in path:
                        self.changed_vpn_configs.add(vpn_name)
            elif path.endswith('.rules'):
                self.changed_files_by_type["networkd"] = True
            elif path.endswith('.service'):
                self.changed_files_by_type["service"] = True
                # Extract VPN name from service file
                if "vpn-ns-" in path:
                    vpn_name = path_obj.name.split("vpn-ns-")[1].split(".")[0]
                    self.changed_vpn_configs.add(vpn_name)
            elif "/rt_tables.d/" in path:
                self.changed_files_by_type["routing"] = True
                # Extract VPN name from routing table
                vpn_name = path_obj.stem
                self.changed_vpn_configs.add(vpn_name)
                
        except Exception as e:
            logger.error(f"Error writing {path}: {e}")
            result["error"] = True
            
        return result
    
    def apply_configuration(self) -> None:
        """Apply the configuration to the system"""
        if not self.load_configuration():
            logger.error("Failed to load configuration files")
            sys.exit(1)
            
        if not self.validate_configuration():
            logger.error("Configuration validation failed")
            sys.exit(1)
            
        self.prune_expired_clients()
        self.resolve_hostname_assignments()
        
        generated_files = self.generate_networkd_files()
        
        if self.dry_run:
            logger.info("=== DRY RUN MODE - No changes will be made ===")
            for file_path, content in generated_files.items():
                logger.info(f"Would write to {file_path}:")
                logger.info("-" * 40)
                # Add newline before content for better readability in logs
                logger.info(f"\n{content}")
                logger.info("-" * 40)
            logger.info("Would reload/restart services as needed based on changes")
            return
        
        # Reset change tracking
        self.changed_files_by_type = {
            "networkd": False,
            "service": False,
            "routing": False
        }
        self.changed_vpn_configs = set()
        
        # Try to get systemd-network group ID
        try:
            systemd_network_gid = grp.getgrnam('systemd-network').gr_gid
        except KeyError:
            logger.warning("systemd-network group not found, using root group for network files")
            systemd_network_gid = 0  # root group
        
        # Process each file and track what types of files have changed
        for file_path, content in generated_files.items():
            result = self.write_file(file_path, content)
            
            if result["changed"]:
                path = Path(file_path)
                
                # Set appropriate permissions based on file type
                if path.name.endswith('.netdev') or path.name.endswith('.network') or path.name.endswith('.rules'):
                    # networkd files: owner root, group systemd-network, permissions 640
                    os.chown(path, 0, systemd_network_gid)
                    os.chmod(path, 0o640)
                    logger.debug(f"Set permissions on {file_path}: 0640, root:systemd-network")
                        
                elif "PrivateKey" in content:
                    # Files with private keys: owner root, group root, permissions 600
                    os.chown(path, 0, 0)
                    os.chmod(path, 0o600)
                    logger.debug(f"Set permissions on {file_path}: 0600, root:root")
                else:
                    # Other files: standard permissions
                    os.chmod(path, 0o644)
        
        # Apply service changes with appropriate reload/restart strategy
        # Only reload/restart what's necessary based on what changed
        
        # If any service files changed, reload systemd daemon
        if self.changed_files_by_type["service"]:
            logger.info("Service files changed, running systemctl daemon-reload")
            subprocess.run(["systemctl", "daemon-reload"])
        
        # If any networkd files changed, reload networkd
        if self.changed_files_by_type["networkd"]:
            logger.info("Network configuration changed, reloading systemd-networkd")
            subprocess.run(["networkctl", "reload"])
        
        # For each VPN in our configuration
        for vpn in self.vpn_definitions["vpn_connections"]:
            vpn_name = vpn["name"]
            service_name = f"vpn-ns-{vpn_name}.service"
            
            # Enable the service (idempotent operation)
            logger.info(f"Ensuring {service_name} is enabled")
            subprocess.run(["systemctl", "enable", service_name])
            
            # Check if service already exists and is running
            service_active = subprocess.run(
                ["systemctl", "is-active", service_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout.decode().strip() == "active"
            
            # Check if the namespace is properly configured
            if not self.dry_run:
                ns_status = self.check_namespace_status(vpn_name)
                
                # Only restart if:
                # 1. Service is not active, OR
                # 2. Namespace doesn't exist or is not properly configured, OR
                # 3. This VPN's configuration files changed
                needs_restart = (
                    not service_active or 
                    not ns_status["exists"] or
                    not ns_status["veth_configured"] or
                    not ns_status["routes_configured"] or
                    not ns_status["nat_configured"] or
                    vpn_name in self.changed_vpn_configs
                )
                
                if needs_restart:
                    # Log detailed reason for restart
                    if not service_active:
                        logger.info(f"Service {service_name} not active, will start it")
                    elif not ns_status["exists"]:
                        logger.info(f"Network namespace for {vpn_name} doesn't exist, will create it")
                    elif not ns_status["veth_configured"]:
                        logger.info(f"Veth interface for {vpn_name} not properly configured, will reconfigure")
                    elif not ns_status["routes_configured"]:
                        logger.info(f"Routes for {vpn_name} not properly configured, will reconfigure")
                    elif not ns_status["nat_configured"]:
                        logger.info(f"NAT for {vpn_name} not properly configured, will reconfigure")
                    elif vpn_name in self.changed_vpn_configs:
                        logger.info(f"Configuration for {vpn_name} changed, will restart service")
                    
                    logger.info(f"Starting/restarting {service_name}")
                    subprocess.run(["systemctl", "restart", service_name])
                else:
                    logger.info(f"Network namespace for {vpn_name} already properly configured, skipping restart")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="VPN Router State Enforcement Script")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    group.add_argument("--validate", action="store_true", help="Validate the configuration only")
    args = parser.parse_args()
    
    # Set UTC time for logging
    os.environ['TZ'] = 'UTC'
    
    router = VpnRouter(dry_run=args.dry_run)
    
    if args.validate:
        if router.load_configuration() and router.validate_configuration():
            logger.info("Configuration validation passed")
            sys.exit(0)
        else:
            logger.error("Configuration validation failed")
            sys.exit(1)
    else:
        router.apply_configuration()

if __name__ == "__main__":
    main()