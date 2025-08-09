#!/usr/bin/env python3
"""
VPN Policy Router Application

This script applies VPN routing policies based on client assignments.
"""

import os
import re
import sys
import json
import hashlib
import logging
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Union, Optional
from datetime import datetime, timezone

# Constants
CONFIG_DIR = Path("/etc/vpn-router")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
NETWORKD_PATH = Path("/etc/systemd/network")

# Default resource ranges
DEFAULT_ROUTING_TABLE_ID_MIN = 7001
DEFAULT_ROUTING_TABLE_ID_MAX = 7200
DEFAULT_VETH_NETWORK_PREFIX = "10.239"

# ANSI colors for terminal output
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
RED = '\033[0;31m'
NC = '\033[0m'  # No Color

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/vpn-router.log')
    ]
)
logger = logging.getLogger('vpn-router')

class VPNRouter:
    """
    VPN Router class to manage policy-based routing for multiple VPN connections
    """
    
    def __init__(self, dry_run=False, auto_mode=False, force_overwrite=False, clean_orphaned=False):
        """Initialize the VPN Router"""
        self.dry_run = dry_run
        self.auto_mode = auto_mode
        self.force_overwrite = force_overwrite
        self.clean_orphaned = clean_orphaned
        
        # Configuration data
        self.vpn_definitions = {}
        self.client_assignments = {}
        self.resolved_assignments = []
        
        # Resource ranges (will be loaded from config)
        self.routing_table_id_min = DEFAULT_ROUTING_TABLE_ID_MIN
        self.routing_table_id_max = DEFAULT_ROUTING_TABLE_ID_MAX
        self.veth_network_prefix = DEFAULT_VETH_NETWORK_PREFIX
        
        # Track active and removed VPNs
        self.active_vpns = set()
        self.removed_vpns = set()
        
        # Current timestamp and user login
        self.current_timestamp = "2025-08-09 19:49:21"  # Updated timestamp
        self.current_user = "gtstudyes"  # User login
        
        logger.info(f"VPN Router initialized by {self.current_user} at {self.current_timestamp} (dry_run={dry_run}, auto_mode={auto_mode}, force_overwrite={force_overwrite})")
        
    def load_configuration(self) -> bool:
        """Load and validate configuration files"""
        try:
            # Load VPN definitions
            with open(VPN_DEFINITIONS_PATH, 'r') as f:
                self.vpn_definitions = json.load(f)
                
            # Load client assignments
            with open(VPN_CLIENTS_PATH, 'r') as f:
                self.client_assignments = json.load(f)
                
            # Extract system configuration or use defaults
            if "system_config" in self.vpn_definitions:
                sys_config = self.vpn_definitions["system_config"]
                if "routing_table_id_range" in sys_config:
                    self.routing_table_id_min = sys_config["routing_table_id_range"].get("min", DEFAULT_ROUTING_TABLE_ID_MIN)
                    self.routing_table_id_max = sys_config["routing_table_id_range"].get("max", DEFAULT_ROUTING_TABLE_ID_MAX)
                else:
                    logger.warning("No routing_table_id_range found in system_config, using defaults")
                
                if "veth_network_range" in sys_config:
                    self.veth_network_prefix = sys_config["veth_network_range"].get("prefix", DEFAULT_VETH_NETWORK_PREFIX)
                else:
                    logger.warning("No veth_network_range found in system_config, using defaults")
            else:
                logger.warning("No system_config found in vpn-definitions.json, using default ranges")
                
            logger.info(f"Configuration loaded successfully")
            logger.info(f"Using routing table ID range: {self.routing_table_id_min}-{self.routing_table_id_max}")
            logger.info(f"Using veth network prefix: {self.veth_network_prefix}")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            return False
        except FileNotFoundError as e:
            logger.error(f"Configuration file not found: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def validate_configuration(self) -> bool:
        """Validate the configuration"""
        valid = True
        
        # Check that VPN definitions exist
        if "vpn_connections" not in self.vpn_definitions:
            logger.error("Missing vpn_connections in VPN definitions")
            return False
            
        # Check that client assignments exist
        if "assignments" not in self.client_assignments:
            logger.error("Missing assignments in client assignments")
            return False
            
        # Track used IDs and networks to check for duplicates
        used_table_ids = set()
        used_networks = set()
        
        # Validate each VPN connection
        for vpn in self.vpn_definitions["vpn_connections"]:
            # Check required fields
            required_fields = ["name", "peer_endpoint", "peer_public_key", "client_private_key", 
                              "vpn_assigned_ip", "routing_table_id", "veth_network"]
                              
            for field in required_fields:
                if field not in vpn:
                    logger.error(f"Missing required field '{field}' in VPN '{vpn.get('name', '(unnamed)')}'")
                    valid = False
            
            # Validate routing_table_id is in range
            if "routing_table_id" in vpn:
                try:
                    table_id = int(vpn["routing_table_id"])
                    if not (self.routing_table_id_min <= table_id <= self.routing_table_id_max):
                        logger.error(f"Routing table ID {table_id} for VPN '{vpn['name']}' is outside configured range " +
                                    f"({self.routing_table_id_min}-{self.routing_table_id_max})")
                        valid = False
                        
                    # Check for duplicate table IDs
                    if table_id in used_table_ids:
                        logger.error(f"Duplicate routing table ID {table_id} used by VPN '{vpn['name']}'")
                        valid = False
                    used_table_ids.add(table_id)
                except ValueError:
                    logger.error(f"Invalid routing table ID '{vpn['routing_table_id']}' for VPN '{vpn['name']}'")
                    valid = False
                
            # Validate veth_network uses our prefix
            if "veth_network" in vpn:
                network = vpn["veth_network"]
                if not network.startswith(f"{self.veth_network_prefix}."):
                    logger.error(f"veth network {network} for VPN '{vpn['name']}' is outside configured range " +
                                f"(should start with {self.veth_network_prefix})")
                    valid = False
                    
                # Check for duplicate networks
                if network in used_networks:
                    logger.error(f"Duplicate veth network {network} used by VPN '{vpn['name']}'")
                    valid = False
                used_networks.add(network)
        
        # Validate client assignments
        for client in self.client_assignments["assignments"]:
            # Check required fields
            if "client_ip" not in client and "hostname" not in client:
                logger.error(f"Client must have either client_ip or hostname: {client}")
                valid = False
                
            if "assigned_vpn" in client:
                # Check that assigned VPN exists
                vpn_exists = any(vpn["name"] == client["assigned_vpn"] 
                                for vpn in self.vpn_definitions["vpn_connections"])
                if not vpn_exists:
                    logger.error(f"Client {client.get('display_name', client.get('client_ip', client.get('hostname', 'unknown')))} " +
                                f"is assigned to non-existent VPN '{client['assigned_vpn']}'")
                    valid = False
        
        logger.info(f"Configuration validation {'passed' if valid else 'failed'}")
        return valid
    
    def resolve_hostname_assignments(self) -> None:
        """Resolve hostnames to IPs for client assignments"""
        logger.info("Resolving hostname assignments...")
        
        self.resolved_assignments = []
        
        for client in self.client_assignments["assignments"]:
            resolved_client = client.copy()
            
            # If client already has an IP, use it
            if "client_ip" in client:
                resolved_client["resolved_ip"] = client["client_ip"]
                self.resolved_assignments.append(resolved_client)
                continue
                
            # If client has a hostname, try to resolve it
            if "hostname" in client:
                hostname = client["hostname"]
                try:
                    # Use getent hosts to resolve hostname
                    result = subprocess.run(
                        ["getent", "hosts", hostname], 
                        capture_output=True, 
                        text=True
                    )
                    
                    if result.returncode == 0:
                        # Extract the first IP from the output
                        ip = result.stdout.split()[0]
                        resolved_client["resolved_ip"] = ip
                        logger.info(f"Resolved hostname {hostname} to {ip}")
                        self.resolved_assignments.append(resolved_client)
                    else:
                        logger.error(f"Failed to resolve hostname {hostname}")
                except Exception as e:
                    logger.error(f"Error resolving hostname {hostname}: {e}")
            else:
                logger.warning(f"Client has neither client_ip nor hostname: {client}")
                
        logger.info(f"Resolved {len(self.resolved_assignments)} client assignments")
    
    def identify_active_and_removed_vpns(self) -> None:
        """Identify which VPNs are active and which need to be removed"""
        # Get all VPN names from the current config
        self.active_vpns = {vpn["name"] for vpn in self.vpn_definitions["vpn_connections"]}
        
        # Find previously configured VPNs that are no longer in the config
        existing_vpns = set()
        
        # Check network namespaces
        try:
            ns_output = subprocess.run(["ip", "netns", "list"], 
                                      capture_output=True, text=True).stdout
            
            for line in ns_output.splitlines():
                if line.strip() and line.strip().startswith("ns-"):
                    vpn_name = line.strip().split("ns-")[1].split()[0]  # Extract name from "ns-<name>"
                    existing_vpns.add(vpn_name)
        except Exception as e:
            logger.error(f"Error checking network namespaces: {e}")
            
        # Check interfaces
        try:
            if_output = subprocess.run(["ip", "link", "show"], 
                                      capture_output=True, text=True).stdout
            
            # Look for interfaces matching our pattern
            if_pattern = re.compile(r"v-([a-zA-Z0-9_-]+)-[wvp]")
            for match in if_pattern.finditer(if_output):
                vpn_name = match.group(1)
                existing_vpns.add(vpn_name)
        except Exception as e:
            logger.error(f"Error checking network interfaces: {e}")
            
        # Identify removed VPNs
        self.removed_vpns = existing_vpns - self.active_vpns
        
        logger.info(f"Found {len(self.active_vpns)} active VPNs")
        logger.info(f"Found {len(self.removed_vpns)} VPNs to remove: {', '.join(self.removed_vpns) if self.removed_vpns else 'none'}")
    
    def cleanup_removed_vpns(self) -> None:
        """Clean up VPNs that have been removed from configuration"""
        if not self.removed_vpns:
            logger.info("No VPNs to remove")
            return
            
        if self.dry_run:
            logger.info("=== DRY RUN MODE - Would clean up removed VPNs ===")
            for vpn_name in self.removed_vpns:
                logger.info(f"Would remove VPN: {vpn_name}")
            return
            
        for vpn_name in self.removed_vpns:
            logger.info(f"Cleaning up removed VPN: {vpn_name}")
            
            # Stop and disable systemd service if exists
            service_name = f"vpn-ns-{vpn_name}.service"
            try:
                # Check if service exists
                service_check = subprocess.run(
                    ["systemctl", "status", service_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if service_check.returncode != 4:  # 4 = unit not found
                    logger.info(f"Stopping and disabling service: {service_name}")
                    subprocess.run(["systemctl", "stop", service_name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["systemctl", "disable", service_name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                logger.error(f"Error stopping service {service_name}: {e}")
                
            # Remove network namespace
            try:
                ns_name = f"ns-{vpn_name}"
                ns_check = subprocess.run(
                    ["ip", "netns", "list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if ns_name in ns_check.stdout:
                    logger.info(f"Removing network namespace: {ns_name}")
                    subprocess.run(["ip", "netns", "del", ns_name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                logger.error(f"Error removing network namespace ns-{vpn_name}: {e}")
                
            # Remove veth interfaces
            interface_prefixes = [f"v-{vpn_name}-v", f"v-{vpn_name}-p", f"v-{vpn_name}-w"]
            for prefix in interface_prefixes:
                try:
                    logger.info(f"Removing interface if exists: {prefix}")
                    # Try to delete interface (will fail silently if it doesn't exist)
                    subprocess.run(["ip", "link", "del", prefix],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except Exception as e:
                    logger.error(f"Error removing interface {prefix}: {e}")
                    
            # Remove routing table entries
            try:
                rt_tables_d_path = Path("/etc/iproute2/rt_tables.d")
                if rt_tables_d_path.exists():
                    for file_path in rt_tables_d_path.glob(f"{vpn_name}_*.conf"):
                        logger.info(f"Removing routing table file: {file_path}")
                        file_path.unlink(missing_ok=True)
            except Exception as e:
                logger.error(f"Error removing routing table files for {vpn_name}: {e}")
                
            # Remove systemd-networkd config files
            try:
                for pattern in [f"10-v-{vpn_name}-*.netdev", f"10-v-{vpn_name}-*.network", 
                               f"20-v-{vpn_name}-*.netdev", f"20-v-{vpn_name}-*.network",
                               f"50-{vpn_name}-client-*.network"]:  # Changed from .rules to .network
                    for file_path in NETWORKD_PATH.glob(pattern):
                        logger.info(f"Removing networkd file: {file_path}")
                        file_path.unlink(missing_ok=True)
            except Exception as e:
                logger.error(f"Error removing networkd files for {vpn_name}: {e}")
                
            # Remove systemd service file
            try:
                service_path = Path(f"/etc/systemd/system/{service_name}")
                if service_path.exists():
                    logger.info(f"Removing service file: {service_path}")
                    service_path.unlink()
            except Exception as e:
                logger.error(f"Error removing service file {service_name}: {e}")
                
        # Reload systemd and networkd
        try:
            logger.info("Reloading systemd daemon")
            subprocess.run(["systemctl", "daemon-reload"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                          
            logger.info("Reloading networkd")
            subprocess.run(["networkctl", "reload"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logger.error(f"Error reloading services: {e}")
            
        logger.info("Cleanup of removed VPNs completed")
    
    def write_file_with_marker(self, path: Path, content: str, vpn_name: str) -> bool:
        """Write a file with a marker identifying it as generated by VPN Router"""
        timestamp = self.current_timestamp  # Use the provided timestamp
        
        # Calculate checksum of the actual content (without the marker)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Create a marker that includes:
        # 1. Identification as a VPN Router generated file
        # 2. The VPN name this file is associated with
        # 3. A timestamp for debugging
        # 4. A checksum of the file content (excluding marker)
        # 5. The user who generated it
        marker = (f"# Generated by VPN-Router v1.0\n"
                  f"# Associated VPN: {vpn_name}\n"
                  f"# Generated at: {timestamp}\n"
                  f"# Generated by: {self.current_user}\n"
                  f"# Content-Hash: {content_hash}\n"
                  f"# DO NOT EDIT: Changes may be lost on next update\n\n")
        
        # Add marker to beginning of file
        marked_content = marker + content
        
        try:
            # Ensure parent directories exist
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the file
            with open(path, 'w') as f:
                f.write(marked_content)
                
            logger.info(f"Wrote file: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write file {path}: {e}")
            return False
    
    def generate_veth_netdev_file(self, vpn: Dict) -> None:
        """Generate veth netdev configuration file"""
        vpn_name = vpn["name"]
        content = f"""[NetDev]
Name=v-{vpn_name}-v
Kind=veth

[Peer]
Name=v-{vpn_name}-p
"""
        file_path = NETWORKD_PATH / f"10-v-{vpn_name}-veth.netdev"
        if self.dry_run:
            logger.info(f"Would write netdev file: {file_path}")
            return
            
        self.write_file_with_marker(file_path, content, vpn_name)
    
    def generate_veth_network_file(self, vpn: Dict) -> None:
        """Generate veth network configuration file"""
        vpn_name = vpn["name"]
        veth_network = vpn["veth_network"]
        ip_parts = veth_network.split('/')
        network = ip_parts[0]
        prefix = ip_parts[1] if len(ip_parts) > 1 else "30"
        
        # For a /30 network, .1 is the first usable address
        veth_ip = network.rsplit('.', 1)[0] + ".1"
        
        content = f"""[Match]
Name=v-{vpn_name}-v

[Network]
Address={veth_ip}/{prefix}
IPForward=yes
"""
        file_path = NETWORKD_PATH / f"10-v-{vpn_name}-veth.network"
        if self.dry_run:
            logger.info(f"Would write network file: {file_path}")
            return
            
        self.write_file_with_marker(file_path, content, vpn_name)
    
    def generate_wireguard_netdev_file(self, vpn: Dict) -> None:
        """Generate WireGuard netdev configuration file"""
        vpn_name = vpn["name"]
        peer_public_key = vpn["peer_public_key"]
        peer_endpoint = vpn["peer_endpoint"]
        client_private_key = vpn["client_private_key"]
        
        content = f"""[NetDev]
Name=v-{vpn_name}-w
Kind=wireguard

[WireGuard]
PrivateKey={client_private_key}

[WireGuardPeer]
PublicKey={peer_public_key}
Endpoint={peer_endpoint}
AllowedIPs=0.0.0.0/0
PersistentKeepalive=25
"""
        file_path = NETWORKD_PATH / f"20-v-{vpn_name}-wireguard.netdev"
        if self.dry_run:
            logger.info(f"Would write wireguard netdev file: {file_path}")
            return
            
        self.write_file_with_marker(file_path, content, vpn_name)
    
    def generate_wireguard_network_file(self, vpn: Dict) -> None:
        """Generate WireGuard network configuration file"""
        vpn_name = vpn["name"]
        vpn_assigned_ip = vpn["vpn_assigned_ip"]
        
        content = f"""[Match]
Name=v-{vpn_name}-w

[Network]
Address={vpn_assigned_ip}
IPForward=yes
"""
        file_path = NETWORKD_PATH / f"20-v-{vpn_name}-wireguard.network"
        if self.dry_run:
            logger.info(f"Would write wireguard network file: {file_path}")
            return
            
        self.write_file_with_marker(file_path, content, vpn_name)
    
    def generate_routing_table_file(self, vpn: Dict) -> None:
        """Generate routing table configuration file"""
        vpn_name = vpn["name"]
        table_id = vpn["routing_table_id"]
        table_name = vpn.get("routing_table_name", f"{vpn_name}vpn")
        
        content = f"{table_id} {table_name}"
        file_path = Path(f"/etc/iproute2/rt_tables.d/{vpn_name}_vpn.conf")
        
        if self.dry_run:
            logger.info(f"Would write routing table file: {file_path}")
            return
            
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the file with marker
            self.write_file_with_marker(file_path, content, vpn_name)
        except Exception as e:
            logger.error(f"Failed to write routing table file {file_path}: {e}")
    
    def generate_client_routing_rules(self, vpn: Dict, client_index: int = 0) -> None:
        """Generate routing rules for VPN clients"""
        vpn_name = vpn["name"]
        table_id = vpn["routing_table_id"]
        
        # Find clients assigned to this VPN
        vpn_clients = [client for client in self.resolved_assignments 
                       if client.get("assigned_vpn") == vpn_name]
        
        if not vpn_clients:
            logger.info(f"No clients assigned to VPN {vpn_name}, skipping rules")
            return
            
        # Generate rules for each client
        for client_index, client in enumerate(vpn_clients):
            client_ip = client["resolved_ip"]
            client_name = client.get("display_name", client_ip.replace('.', '_'))
            
            # Sanitize client name for filename
            safe_client_name = re.sub(r'[^a-zA-Z0-9_-]', '_', client_name)
            
            # Corrected: Use .network file with [RoutingPolicyRule] section
            content = f"""[Match]
Name=*

[RoutingPolicyRule]
From={client_ip}
Table={table_id}
Priority=100
"""
            # Corrected: Use .network extension instead of .rules
            file_path = NETWORKD_PATH / f"50-{vpn_name}-client-{safe_client_name}.network"
            
            if self.dry_run:
                logger.info(f"Would write client rule file: {file_path}")
                continue
                
            self.write_file_with_marker(file_path, content, vpn_name)
    
    def generate_vpn_service_file(self, vpn: Dict) -> None:
        """Generate systemd service file for VPN namespace"""
        vpn_name = vpn["name"]
        table_id = vpn["routing_table_id"]
        router_lan_interface = vpn.get("router_lan_interface", "eth0")
        
        content = f"""[Unit]
Description=VPN Policy Router for {vpn_name}
After=network.target systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/ip netns add ns-{vpn_name}
ExecStart=/usr/bin/ip link set v-{vpn_name}-p netns ns-{vpn_name}
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} ip link set v-{vpn_name}-p up
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} ip link set lo up
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} ip link add v-{vpn_name}-w type wireguard
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} wg setconf v-{vpn_name}-w /etc/systemd/network/20-v-{vpn_name}-wireguard.conf
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} ip link set v-{vpn_name}-w up

# Set up IP addresses and routing in the namespace
ExecStart=/usr/bin/ip -n ns-{vpn_name} addr add {vpn["vpn_assigned_ip"]} dev v-{vpn_name}-w
ExecStart=/usr/bin/ip -n ns-{vpn_name} addr add {vpn["veth_network"].split('/')[0].rsplit('.', 1)[0]}.2/30 dev v-{vpn_name}-p
ExecStart=/usr/bin/ip -n ns-{vpn_name} route add default dev v-{vpn_name}-w

# Set up NAT in the namespace
ExecStart=/usr/bin/ip netns exec ns-{vpn_name} iptables -t nat -A POSTROUTING -o v-{vpn_name}-w -j MASQUERADE

# Add the needed route in the main namespace for clients to reach the VPN
ExecStart=/usr/bin/ip route add {vpn["veth_network"]} dev v-{vpn_name}-v
ExecStart=/usr/bin/ip route add default via {vpn["veth_network"].split('/')[0].rsplit('.', 1)[0]}.2 table {table_id}

# Configure masquerade for the return path
ExecStart=/usr/bin/iptables -t nat -A POSTROUTING -o {router_lan_interface} -j MASQUERADE

ExecStop=/usr/bin/ip route del default via {vpn["veth_network"].split('/')[0].rsplit('.', 1)[0]}.2 table {table_id} || true
ExecStop=/usr/bin/ip route del {vpn["veth_network"]} || true
ExecStop=/usr/bin/ip link del v-{vpn_name}-v || true
ExecStop=/usr/bin/ip netns del ns-{vpn_name} || true

[Install]
WantedBy=multi-user.target
"""
        file_path = Path(f"/etc/systemd/system/vpn-ns-{vpn_name}.service")
        
        if self.dry_run:
            logger.info(f"Would write service file: {file_path}")
            return
            
        try:
            # Write the file with marker
            self.write_file_with_marker(file_path, content, vpn_name)
            
            # Make sure permissions are correct
            os.chmod(file_path, 0o644)
        except Exception as e:
            logger.error(f"Failed to write service file {file_path}: {e}")
    
    def setup_vpn(self, vpn: Dict) -> None:
        """Set up a single VPN connection"""
        vpn_name = vpn["name"]
        logger.info(f"Setting up VPN: {vpn_name}")
        
        if self.dry_run:
            logger.info(f"=== DRY RUN MODE - Would set up VPN: {vpn_name} ===")
        
        # Generate configuration files
        self.generate_veth_netdev_file(vpn)
        self.generate_veth_network_file(vpn)
        self.generate_wireguard_netdev_file(vpn)
        self.generate_wireguard_network_file(vpn)
        self.generate_routing_table_file(vpn)
        self.generate_client_routing_rules(vpn)
        self.generate_vpn_service_file(vpn)
        
        if self.dry_run:
            return
            
        # Enable and start the service
        try:
            logger.info(f"Enabling and starting service: vpn-ns-{vpn_name}.service")
            subprocess.run(["systemctl", "enable", f"vpn-ns-{vpn_name}.service"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["systemctl", "restart", f"vpn-ns-{vpn_name}.service"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logger.error(f"Error enabling/starting service vpn-ns-{vpn_name}.service: {e}")
    
    def check_for_modified_files(self) -> List[Dict]:
        """Find files with our marker that have been modified using checksum verification"""
        modified_files = []
        
        # Define our file patterns
        file_patterns = [
            "10-v-*.netdev",
            "10-v-*.network",
            "20-v-*.netdev",
            "20-v-*.network",
            "50-*-client-*.network"  # Changed from .rules to .network
        ]
        
        # Look for our marker in files
        marker_pattern = re.compile(r"# Generated by VPN-Router v1\.0\n"
                                  r"# Associated VPN: ([a-zA-Z0-9_-]+)\n"
                                  r"# Generated at: .+\n"
                                  r"# Generated by: .+\n"  # Added user info
                                  r"# Content-Hash: ([a-f0-9]+)\n"
                                  r"# DO NOT EDIT: .+\n\n")
        
        for pattern in file_patterns:
            for file_path in NETWORKD_PATH.glob(pattern):
                try:
                    # Read file content
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Check if it has our marker
                    match = marker_pattern.search(content)
                    if match:
                        vpn_name = match.group(1)
                        stored_hash = match.group(2)
                        
                        # Extract the content part (everything after the marker)
                        marker_end = match.end()
                        file_content = content[marker_end:]
                        
                        # Calculate hash of the actual content
                        actual_hash = hashlib.sha256(file_content.encode()).hexdigest()
                        
                        # Compare hashes
                        if actual_hash != stored_hash:
                            logger.warning(f"File {file_path} has been modified manually (hash mismatch)")
                            modified_files.append({
                                "path": str(file_path),
                                "vpn_name": vpn_name,
                                "expected_hash": stored_hash,
                                "actual_hash": actual_hash
                            })
                except Exception as e:
                    logger.warning(f"Error checking file {file_path}: {e}")
        
        return modified_files
    
    def handle_modified_files(self, modified_files: List[Dict]) -> None:
        """Handle files that have been modified"""
        if not modified_files:
            return
            
        logger.warning(f"Found {len(modified_files)} files with manual modifications:")
        for file in modified_files:
            logger.warning(f"  - {file['path']} (VPN: {file['vpn_name']})")
        
        # Notify user about modified files
        if not self.auto_mode:
            print(f"\n{YELLOW}WARNING:{NC} {len(modified_files)} configuration files have been modified manually.")
            print("These files will NOT be automatically updated or removed to preserve your changes.")
            print("Please review these files manually:")
            
            for file in modified_files:
                print(f"  - {file['path']}")
                
            print("\nYou may need to manually reconcile these files with the current configuration.")
            print(f"To force overwrite of these files, run with {YELLOW}--force-overwrite{NC}")
            
        # If force_overwrite is enabled, regenerate these files
        if self.force_overwrite:
            logger.warning("Force overwrite enabled, overwriting modified files")
            for file in modified_files:
                file_path = Path(file['path'])
                vpn_name = file['vpn_name']
                
                # Find the corresponding VPN configuration
                vpn = None
                for v in self.vpn_definitions["vpn_connections"]:
                    if v["name"] == vpn_name:
                        vpn = v
                        break
                        
                if vpn:
                    logger.info(f"Regenerating modified file: {file_path}")
                    # Determine the type of file and regenerate it
                    if "10-v" in file_path.name and "veth.netdev" in file_path.name:
                        self.generate_veth_netdev_file(vpn)
                    elif "10-v" in file_path.name and "veth.network" in file_path.name:
                        self.generate_veth_network_file(vpn)
                    elif "20-v" in file_path.name and "wireguard.netdev" in file_path.name:
                        self.generate_wireguard_netdev_file(vpn)
                    elif "20-v" in file_path.name and "wireguard.network" in file_path.name:
                        self.generate_wireguard_network_file(vpn)
                    elif "50-" in file_path.name and "client-" in file_path.name:
                        self.generate_client_routing_rules(vpn)
                else:
                    logger.warning(f"Could not find VPN configuration for {vpn_name}, skipping regeneration")
    
    def clean_orphaned_resources(self) -> Dict[str, int]:
        """
        Clean up orphaned resources created by the VPN router system
        
        Returns:
            Dictionary with counts of cleaned resources by type
        """
        if self.dry_run:
            logger.info("=== DRY RUN MODE - Would clean orphaned resources ===")
            return {"dry_run": True}
        
        # Initialize counters for cleaned resources
        cleaned = {
            "namespaces": 0,
            "interfaces": 0,
            "routing_tables": 0,
            "routing_rules": 0,
            "services": 0,
            "files": 0
        }
        
        # Get current active resources
        active_vpn_names = {vpn["name"] for vpn in self.vpn_definitions["vpn_connections"]}
        active_vpn_table_ids = {int(vpn["routing_table_id"]) for vpn in self.vpn_definitions["vpn_connections"]
                                if "routing_table_id" in vpn and vpn["routing_table_id"].isdigit()}
        active_vpn_networks = {vpn["veth_network"] for vpn in self.vpn_definitions["vpn_connections"]
                             if "veth_network" in vpn}
        
        # First check for modified files to avoid touching them
        modified_files = self.check_for_modified_files()
        modified_paths = {Path(file["path"]) for file in modified_files}
        
        # 1. Clean up orphaned network namespaces
        logger.info("Cleaning up orphaned network namespaces...")
        ns_list = subprocess.run(["ip", "netns", "list"], 
                                capture_output=True, text=True).stdout
        
        for line in ns_list.splitlines():
            if not line.strip():
                continue
                
            # Extract namespace name (format is "ns-{vpn_name}")
            ns_name = line.split(' ')[0].strip()
            if ns_name.startswith("ns-"):
                vpn_name = ns_name[3:]  # Remove "ns-" prefix
                
                if vpn_name not in active_vpn_names:
                    logger.info(f"Cleaning up orphaned network namespace: {ns_name}")
                    
                    # Clean up any nftables rules in the namespace first
                    subprocess.run(["ip", "netns", "exec", ns_name, "nft", "flush", "ruleset"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Delete the namespace
                    result = subprocess.run(["ip", "netns", "del", ns_name],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    if result.returncode == 0:
                        logger.info(f"Successfully removed namespace: {ns_name}")
                        cleaned["namespaces"] += 1
                    else:
                        logger.error(f"Failed to remove namespace {ns_name}: {result.stderr.decode()}")
        
        # 2. Clean up orphaned interfaces
        logger.info("Cleaning up orphaned network interfaces...")
        
        # First by name pattern
        if_list = subprocess.run(["ip", "link", "show"], 
                                capture_output=True, text=True).stdout
        
        interface_pattern = re.compile(r"\d+:\s+(v-([a-zA-Z0-9_-]+)-[wvp])[@:]")
        
        for line in if_list.splitlines():
            match = interface_pattern.search(line)
            if match:
                if_name = match.group(1)
                vpn_name = match.group(2)
                
                if vpn_name not in active_vpn_names:
                    logger.info(f"Cleaning up orphaned interface: {if_name}")
                    result = subprocess.run(["ip", "link", "del", if_name],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    if result.returncode == 0:
                        logger.info(f"Successfully removed interface: {if_name}")
                        cleaned["interfaces"] += 1
                    else:
                        logger.error(f"Failed to remove interface {if_name}: {result.stderr.decode()}")
        
        # Then by IP range
        addr_output = subprocess.run(["ip", "addr", "show"], 
                                   capture_output=True, text=True).stdout
        
        ip_pattern = re.compile(rf"inet ({self.veth_network_prefix}\.\d+\.\d+)/\d+.+\s(\S+)$", re.MULTILINE)
        
        for match in ip_pattern.finditer(addr_output):
            ip_addr = match.group(1)
            interface = match.group(2)
            
            # Skip interfaces that match our naming pattern (already handled above)
            if re.match(r"v-[a-zA-Z0-9_-]+-[wvp]", interface):
                continue
                
            network_prefix = ip_addr[:ip_addr.rindex(".")] + ".0"  # Convert IP to network prefix
            
            # Check if this network is part of any active VPN
            network_active = False
            for network in active_vpn_networks:
                if network_prefix in network:
                    network_active = True
                    break
                    
            if not network_active:
                logger.info(f"Cleaning up orphaned interface by IP: {interface} ({ip_addr})")
                result = subprocess.run(["ip", "link", "del", interface],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    logger.info(f"Successfully removed interface: {interface}")
                    cleaned["interfaces"] += 1
                else:
                    logger.error(f"Failed to remove interface {interface}: {result.stderr.decode()}")
        
        # 3. Clean up orphaned routing tables and rules
        logger.info("Cleaning up orphaned routing tables and rules...")
        
        # Clean up routing rules first
        rules_list = subprocess.run(["ip", "rule", "list"], 
                                  capture_output=True, text=True).stdout
        
        for line in rules_list.splitlines():
            if "lookup" in line:
                parts = line.split("lookup")
                if len(parts) >= 2:
                    table_ref = parts[1].strip()
                    
                    if table_ref.isdigit():
                        table_id = int(table_ref)
                        
                        if (self.routing_table_id_min <= table_id <= self.routing_table_id_max and 
                            table_id not in active_vpn_table_ids):
                            
                            # Extract priority and from clause
                            priority_match = re.search(r"^(\d+):", line)
                            if priority_match:
                                priority = priority_match.group(1)
                                
                                from_match = re.search(r"from\s+([0-9./]+)", line)
                                from_clause = ""
                                if from_match:
                                    from_clause = f"from {from_match.group(1)}"
                                    
                                # Delete the rule
                                cmd = ["ip", "rule", "del", "priority", priority]
                                if from_clause:
                                    cmd.extend(from_clause.split())
                                    
                                logger.info(f"Cleaning up orphaned routing rule: {line.strip()}")
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                
                                if result.returncode == 0:
                                    logger.info(f"Successfully removed routing rule")
                                    cleaned["routing_rules"] += 1
                                else:
                                    logger.error(f"Failed to remove routing rule: {result.stderr.decode()}")
        
        # Clean up routing tables in rt_tables.d
        rt_tables_d_path = Path("/etc/iproute2/rt_tables.d/")
        if rt_tables_d_path.exists():
            for file_path in rt_tables_d_path.glob("*.conf"):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Check for our marker
                    marker_match = re.search(r"# Generated by VPN-Router v1\.0\n# Associated VPN: ([a-zA-Z0-9_-]+)", content)
                    if marker_match:
                        vpn_name = marker_match.group(1)
                        if vpn_name not in active_vpn_names:
                            logger.info(f"Removing orphaned routing table file with marker: {file_path}")
                            file_path.unlink(missing_ok=True)
                            cleaned["routing_tables"] += 1
                            continue
                    
                    # If no marker, check by table ID
                    rt_pattern = re.compile(r"^(\d+)\s+(.+)$", re.MULTILINE)
                    match = rt_pattern.search(content)
                    if match and match.group(1).isdigit():
                        table_id = int(match.group(1))
                        
                        if (self.routing_table_id_min <= table_id <= self.routing_table_id_max and 
                            table_id not in active_vpn_table_ids):
                            
                            logger.info(f"Removing orphaned routing table file by ID: {file_path}")
                            file_path.unlink(missing_ok=True)
                            cleaned["routing_tables"] += 1
                except Exception as e:
                    logger.warning(f"Error processing routing table file {file_path}: {e}")
        
        # Update main routing tables file if needed
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        if rt_tables_path.exists():
            try:
                with open(rt_tables_path, 'r') as f:
                    rt_tables_content = f.read()
                    
                rt_pattern = re.compile(r"^(\d+)\s+(.+)$", re.MULTILINE)
                matches = rt_pattern.findall(rt_tables_content)
                
                new_content = []
                removed_entries = 0
                
                for line in rt_tables_content.splitlines():
                    match = rt_pattern.match(line)
                    if match and match.group(1).isdigit():
                        table_id = int(match.group(1))
                        
                        if (self.routing_table_id_min <= table_id <= self.routing_table_id_max and 
                            table_id not in active_vpn_table_ids):
                            # Skip this line (remove entry)
                            removed_entries += 1
                            continue
                    
                    new_content.append(line)
                
                # Write back the file if it changed
                if removed_entries > 0:
                    with open(rt_tables_path, 'w') as f:
                        f.write("\n".join(new_content) + "\n")
                    logger.info(f"Updated main routing tables file, removed {removed_entries} orphaned entries")
                    cleaned["routing_tables"] += removed_entries
            except Exception as e:
                logger.error(f"Error updating routing tables file: {e}")
        
        # 4. Clean up systemd services
        logger.info("Cleaning up orphaned systemd services...")
        
        # Look for service files matching our pattern
        for service_path in Path("/etc/systemd/system").glob("vpn-ns-*.service"):
            vpn_name = service_path.name.split("vpn-ns-")[1].split(".")[0]
            
            if vpn_name not in active_vpn_names:
                service_name = service_path.name
                logger.info(f"Found orphaned service: {service_name}")
                
                # Stop and disable the service
                subprocess.run(["systemctl", "stop", service_name],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["systemctl", "disable", service_name],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Check if file has our marker
                try:
                    with open(service_path, 'r') as f:
                        content = f.read()
                        
                    marker_match = re.search(r"# Generated by VPN-Router v1\.0\n# Associated VPN: ([a-zA-Z0-9_-]+)", content)
                    if not marker_match or marker_match.group(1) == vpn_name:
                        # Remove the service file if it has our marker or no marker but matches our naming pattern
                        logger.info(f"Removing orphaned service file: {service_path}")
                        service_path.unlink(missing_ok=True)
                        cleaned["services"] += 1
                    else:
                        logger.warning(f"Service file {service_path} has marker for different VPN, leaving intact")
                except Exception as e:
                    logger.error(f"Error checking service file {service_path}: {e}")
        
        # Run daemon-reload if any services were removed
        if cleaned["services"] > 0:
            logger.info("Running systemctl daemon-reload after removing service files")
            subprocess.run(["systemctl", "daemon-reload"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # 5. Clean up orphaned config files
        logger.info("Cleaning up orphaned configuration files...")
        
        # Find orphaned config files (files with our marker for inactive VPNs)
        for pattern in ["10-v-*.netdev", "10-v-*.network", "20-v-*.netdev", "20-v-*.network", "50-*-client-*.network"]:  # Changed from .rules to .network
            for file_path in NETWORKD_PATH.glob(pattern):
                # Skip if it's in the modified files list
                if file_path in modified_paths:
                    logger.info(f"Skipping modified file: {file_path}")
                    continue
                    
                try:
                    # Read file to check for our marker
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Check if it has our marker and extract VPN name
                    marker_match = re.search(r"# Generated by VPN-Router v1\.0\n# Associated VPN: ([a-zA-Z0-9_-]+)", content)
                    if marker_match:
                        vpn_name = marker_match.group(1)
                        
                        # If VPN is not active, file is orphaned
                        if vpn_name not in active_vpn_names:
                            logger.info(f"Removing orphaned file: {file_path}")
                            file_path.unlink(missing_ok=True)
                            cleaned["files"] += 1
                except Exception as e:
                    logger.warning(f"Error checking file {file_path}: {e}")
        
        # If any networkd files were changed, reload networkd
        if cleaned["files"] > 0:
            logger.info("Reloading networkd after removing configuration files")
            subprocess.run(["networkctl", "reload"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Handle modified files last (just notification, no changes)
        self.handle_modified_files(modified_files)
        
        # Log cleanup summary
        total_cleaned = sum(cleaned.values())
        if total_cleaned > 0:
            logger.info(f"Cleanup completed: {total_cleaned} orphaned resources removed")
            for resource_type, count in cleaned.items():
                if count > 0:
                    logger.info(f"  - {resource_type}: {count}")
        else:
            logger.info("No orphaned resources found to clean up")
            
        return cleaned
    
    def apply_configuration(self) -> None:
        """Apply the configuration to the system"""
        # Load and validate configuration
        if not self.load_configuration():
            logger.error("Failed to load configuration files")
            sys.exit(1)
            
        if not self.validate_configuration():
            logger.error("Configuration validation failed")
            sys.exit(1)
        
        # If clean_orphaned is specified, only clean orphaned resources
        if self.clean_orphaned:
            logger.info("Running orphaned resource cleanup...")
            self.identify_active_and_removed_vpns()
            self.clean_orphaned_resources()
            return
            
        # Prepare client assignments
        self.resolve_hostname_assignments()
        
        # Identify which VPNs are active and which should be removed
        self.identify_active_and_removed_vpns()
        
        # Clean up removed VPNs
        self.cleanup_removed_vpns()
        
        # Set up each active VPN
        for vpn in self.vpn_definitions["vpn_connections"]:
            self.setup_vpn(vpn)
            
        # Reload networkd
        if not self.dry_run:
            logger.info("Reloading networkd")
            subprocess.run(["networkctl", "reload"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
        logger.info("VPN Policy Router configuration applied successfully")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VPN Policy Router")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--auto", action="store_true", help="Run in automatic mode without user prompts")
    parser.add_argument("--force-overwrite", action="store_true", help="Force overwrite of modified files")
    parser.add_argument("--clean-orphaned", action="store_true", help="Clean up orphaned resources")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Set log level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)
        
    # Create VPN Router instance and apply configuration
    router = VPNRouter(
        dry_run=args.dry_run,
        auto_mode=args.auto,
        force_overwrite=args.force_overwrite,
        clean_orphaned=args.clean_orphaned
    )
    
    router.apply_configuration()

if __name__ == "__main__":
    main()
