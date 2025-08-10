#!/usr/bin/env python3
"""
VPN Policy Router Configuration Apply Script
This script applies the VPN router configuration from JSON definitions
"""

import os
import sys
import re
import json
import time
import hashlib
import shutil
import subprocess
import argparse
import logging
import ipaddress
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('vpn-router')

# Base directories
CONFIG_DIR = Path("/etc/vpn-router")
NETWORKD_DIR = Path("/etc/systemd/network")
SYSTEMD_DIR = Path("/etc/systemd/system")

# Config file paths
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"

# Default values
DEFAULT_NETWORK_PREFIX = "10.239"
DEFAULT_MIN_TABLE_ID = 7001
DEFAULT_MAX_TABLE_ID = 7200

# Metadata for generated files
GENERATOR_VERSION = "1.0"
GENERATOR_NAME = "vpn-apply.py"


class VPNRouter:
    """VPN Router configuration manager"""
    
    def __init__(self, dry_run=False, auto_mode=False, force_overwrite=False):
        """Initialize the VPN Router manager"""
        self.dry_run = dry_run
        self.auto_mode = auto_mode
        self.force_overwrite = force_overwrite
        self.changed_files = []
        self.created_resources = []
        self.cleaned_resources = {
            "namespaces": 0,
            "interfaces": 0,
            "routing_tables": 0,
            "routing_rules": 0,
            "services": 0,
            "files": 0
        }
        self.modified_files = []
        
        self.vpn_definitions = self._load_json(VPN_DEFINITIONS_PATH)
        self.vpn_clients = self._load_json(VPN_CLIENTS_PATH)
        
        # Create config skeleton if empty
        if not self.vpn_definitions:
            self.vpn_definitions = {
                "system_config": {
                    "routing_table_id_range": {
                        "min": DEFAULT_MIN_TABLE_ID,
                        "max": DEFAULT_MAX_TABLE_ID
                    },
                    "veth_network_range": {
                        "prefix": DEFAULT_NETWORK_PREFIX
                    }
                },
                "vpn_connections": []
            }
            
        if not self.vpn_clients:
            self.vpn_clients = {
                "assignments": []
            }
            
        # Validate configuration
        self._validate_config()
        
    def _load_json(self, path):
        """Load JSON from file with improved error handling"""
        try:
            if path.exists():
                with open(path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file not found: {path}")
                # Create an empty template file instead of just returning empty dict
                if path == VPN_DEFINITIONS_PATH:
                    template = {
                        "system_config": {
                            "routing_table_id_range": {
                                "min": DEFAULT_MIN_TABLE_ID,
                                "max": DEFAULT_MAX_TABLE_ID
                            },
                            "veth_network_range": {
                                "prefix": DEFAULT_NETWORK_PREFIX
                            }
                        },
                        "vpn_connections": []
                    }
                elif path == VPN_CLIENTS_PATH:
                    template = {
                        "assignments": []
                    }
                else:
                    template = {}
                    
                # In auto mode, create the template file
                if self.auto_mode:
                    logger.info(f"Creating template config file at {path}")
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'w') as f:
                        json.dump(template, f, indent=2)
                return template
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {path}: {e}")
            if self.auto_mode:
                # Try to repair common JSON errors
                logger.info("Attempting to repair JSON file...")
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                    
                    # Backup the original file
                    backup_path = f"{path}.bak.{int(time.time())}"
                    with open(backup_path, 'w') as f:
                        f.write(content)
                    logger.info(f"Original file backed up to {backup_path}")
                    
                    # Try to fix common JSON errors
                    content = re.sub(r',\s*}', '}', content)  # Remove trailing commas
                    content = re.sub(r',\s*]', ']', content)  # Remove trailing commas in arrays
                    
                    # Try to parse the fixed content
                    fixed_data = json.loads(content)
                    
                    # Write back the corrected JSON
                    with open(path, 'w') as f:
                        json.dump(fixed_data, f, indent=2)
                    logger.info(f"JSON file repaired successfully")
                    return fixed_data
                except Exception as repair_error:
                    logger.error(f"Failed to repair JSON: {repair_error}")
                    logger.error("Exiting due to invalid configuration")
                    sys.exit(1)
            else:
                if self._prompt_yes_no(f"Config file {path} contains invalid JSON. Continue with empty config?"):
                    if path == VPN_DEFINITIONS_PATH:
                        return {
                            "system_config": {
                                "routing_table_id_range": {
                                    "min": DEFAULT_MIN_TABLE_ID,
                                    "max": DEFAULT_MAX_TABLE_ID
                                },
                                "veth_network_range": {
                                    "prefix": DEFAULT_NETWORK_PREFIX
                                }
                            },
                            "vpn_connections": []
                        }
                    elif path == VPN_CLIENTS_PATH:
                        return {"assignments": []}
                    else:
                        return {}
                else:
                    logger.error("Exiting due to invalid configuration")
                    sys.exit(1)
        except Exception as e:
            logger.error(f"Error loading config file {path}: {e}")
            if self.auto_mode:
                logger.error("Exiting due to configuration error")
                sys.exit(1)
            else:
                if self._prompt_yes_no(f"Error loading config file {path}. Continue with empty config?"):
                    if path == VPN_DEFINITIONS_PATH:
                        return {
                            "system_config": {
                                "routing_table_id_range": {
                                    "min": DEFAULT_MIN_TABLE_ID,
                                    "max": DEFAULT_MAX_TABLE_ID
                                },
                                "veth_network_range": {
                                    "prefix": DEFAULT_NETWORK_PREFIX
                                }
                            },
                            "vpn_connections": []
                        }
                    elif path == VPN_CLIENTS_PATH:
                        return {"assignments": []}
                    else:
                        return {}
                else:
                    logger.error("Exiting due to configuration error")
                    sys.exit(1)
    
    def _validate_config(self):
        """Validate the configuration files"""
        # Check if system_config exists
        if "system_config" not in self.vpn_definitions:
            logger.error("Missing 'system_config' in vpn-definitions.json")
            sys.exit(1)
        
        # Check for VPN connections
        if "vpn_connections" not in self.vpn_definitions:
            logger.error("Missing 'vpn_connections' in vpn-definitions.json")
            sys.exit(1)
            
        # Check routing table ID range
        routing_range = self.vpn_definitions["system_config"].get("routing_table_id_range", {})
        min_table_id = routing_range.get("min", DEFAULT_MIN_TABLE_ID)
        max_table_id = routing_range.get("max", DEFAULT_MAX_TABLE_ID)
        
        if not isinstance(min_table_id, int) or not isinstance(max_table_id, int):
            logger.error("Invalid routing table ID range: must be integers")
            sys.exit(1)
        
        if min_table_id >= max_table_id:
            logger.error("Invalid routing table ID range: min must be less than max")
            sys.exit(1)
            
        if min_table_id < 1 or max_table_id > 65535:
            logger.error("Invalid routing table ID range: values must be between 1 and 65535")
            sys.exit(1)
        
        # Check network prefix
        network_config = self.vpn_definitions["system_config"].get("veth_network_range", {})
        network_prefix = network_config.get("prefix", DEFAULT_NETWORK_PREFIX)
        
        if not isinstance(network_prefix, str) or not re.match(r'^(\d{1,3})\.(\d{1,3})$', network_prefix):
            logger.error("Invalid network prefix: must be in format X.Y")
            sys.exit(1)
            
        # Validate each VPN connection
        used_table_ids = set()
        used_networks = set()
        used_names = set()
        
        for vpn in self.vpn_definitions["vpn_connections"]:
            # Check required fields
            required_fields = [
                "name", "client_private_key", "client_public_key", 
                "peer_public_key", "peer_endpoint", "vpn_assigned_ip",
                "veth_network", "routing_table_id"
            ]
            
            for field in required_fields:
                if field not in vpn:
                    logger.error(f"Missing required field '{field}' in VPN connection")
                    sys.exit(1)
            
            # Validate name (alphanumeric, no spaces)
            if not re.match(r'^[a-zA-Z0-9_-]+$', vpn["name"]):
                logger.error(f"Invalid VPN name: {vpn['name']} (must contain only alphanumeric, underscore, hyphen)")
                sys.exit(1)
                
            if vpn["name"] in used_names:
                logger.error(f"Duplicate VPN name: {vpn['name']}")
                sys.exit(1)
            used_names.add(vpn["name"])
            
            # Validate routing table ID
            table_id = vpn["routing_table_id"]
            if not isinstance(table_id, int):
                logger.error(f"Invalid routing table ID for VPN {vpn['name']}: must be integer")
                sys.exit(1)
                
            if table_id < min_table_id or table_id > max_table_id:
                logger.error(f"Routing table ID {table_id} out of range ({min_table_id}-{max_table_id})")
                sys.exit(1)
                
            if table_id in used_table_ids:
                logger.error(f"Duplicate routing table ID: {table_id}")
                sys.exit(1)
            used_table_ids.add(table_id)
            
            # Validate VPN assigned IP
            try:
                ipaddress.ip_network(vpn["vpn_assigned_ip"], strict=False)
            except ValueError:
                logger.error(f"Invalid VPN assigned IP: {vpn['vpn_assigned_ip']}")
                sys.exit(1)
                
            # Validate veth network
            try:
                veth_network = ipaddress.ip_network(vpn["veth_network"], strict=False)
                if veth_network.prefixlen > 30:
                    logger.error(f"veth network prefix too small: {vpn['veth_network']}")
                    sys.exit(1)
                    
                for existing_network in used_networks:
                    if veth_network.overlaps(existing_network):
                        logger.error(f"Overlapping veth networks: {vpn['veth_network']} and {existing_network}")
                        sys.exit(1)
                used_networks.add(veth_network)
            except ValueError:
                logger.error(f"Invalid veth network: {vpn['veth_network']}")
                sys.exit(1)
                
            # Validate peer endpoint
            if not re.match(r'^[a-zA-Z0-9.-]+:\d+$', vpn["peer_endpoint"]):
                logger.error(f"Invalid peer endpoint: {vpn['peer_endpoint']} (must be host:port)")
                sys.exit(1)

        # Validate client assignments
        if "assignments" not in self.vpn_clients:
            logger.warning("No client assignments found")
        else:
            for client in self.vpn_clients["assignments"]:
                # Check required fields
                if "assigned_vpn" not in client:
                    logger.error(f"Missing 'assigned_vpn' in client assignment")
                    sys.exit(1)
                    
                if client["assigned_vpn"] not in used_names:
                    logger.error(f"Client assigned to unknown VPN: {client['assigned_vpn']}")
                    sys.exit(1)
                    
                # Check that client has either hostname or IP
                if not client.get("hostname") and not client.get("ip_address"):
                    logger.error(f"Client must have either hostname or IP address")
                    sys.exit(1)
                    
                # If IP is specified, validate it
                if client.get("ip_address"):
                    try:
                        ipaddress.ip_address(client["ip_address"])
                    except ValueError:
                        logger.error(f"Invalid client IP address: {client['ip_address']}")
                        sys.exit(1)
                        
                # Check expiry date format if present
                if client.get("assignment_expiry"):
                    try:
                        datetime.fromisoformat(client["assignment_expiry"].replace("Z", "+00:00"))
                    except ValueError:
                        logger.error(f"Invalid expiry format: {client['assignment_expiry']} (must be ISO format)")
                        sys.exit(1)
        
        logger.info("Configuration validation successful")
    
    def _get_active_vpns(self):
        """
        Determine which VPNs should be active based on client assignments
        
        Returns:
            set: Names of VPNs that should be active
        """
        active_vpns = set()
        
        # Only consider non-direct VPN assignments
        for assignment in self.vpn_clients["assignments"]:
            if assignment["vpn"] != "direct":
                active_vpns.add(assignment["vpn"])
                
        return active_vpns
        
    def _generate_file_metadata(self, content_hash):
        """Generate metadata for managed files"""
        metadata = (
            f"# Generated by {GENERATOR_NAME} v{GENERATOR_VERSION}\n"
            f"# Hash: {content_hash}\n"
            f"# DO NOT EDIT - This file is managed by vpn-router\n\n"
        )
        return metadata
        
    def _calculate_content_hash(self, content):
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
        
    def _extract_hash_from_file(self, file_path):
        """Extract the content hash from file metadata"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Look for the hash line in the metadata
            hash_match = re.search(r'^# Hash: ([a-f0-9]{64})$', content, re.MULTILINE)
            if hash_match:
                return hash_match.group(1)
                
            return None
        except Exception:
            return None
            
    def _extract_content_without_metadata(self, file_content):
        """Extract the file content without metadata"""
        try:
            # Find the end of the metadata section
            metadata_end = file_content.find("# DO NOT EDIT - This file is managed by vpn-router\n\n")
            
            if metadata_end != -1:
                # Return everything after the metadata section
                return file_content[metadata_end + len("# DO NOT EDIT - This file is managed by vpn-router\n\n"):]
            
            return file_content
        except Exception:
            return file_content
            
    def _write_file(self, path, content, mode=0o644):
        """Write content to file with proper error handling"""
        # Add metadata to the content
        content_hash = self._calculate_content_hash(content)
        metadata = self._generate_file_metadata(content_hash)
        full_content = metadata + content
        
        if self.dry_run:
            logger.info(f"Would write to file: {path}")
            return True
            
        try:
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            # Check if file exists and has different content
            file_exists = os.path.exists(path)
            content_changed = True
            is_modified = False
            
            if file_exists:
                try:
                    with open(path, 'r') as f:
                        existing_content = f.read()
                    
                    # Check if the file is managed by vpn-router
                    if "# Generated by vpn-apply.py" in existing_content and "# DO NOT EDIT" in existing_content:
                        # Extract the original hash
                        original_hash = self._extract_hash_from_file(path)
                        
                        if original_hash:
                            # Extract content without metadata
                            existing_content_without_metadata = self._extract_content_without_metadata(existing_content)
                            
                            # Calculate hash of existing content
                            actual_hash = self._calculate_content_hash(existing_content_without_metadata)
                            
                            # Check if the file was manually modified
                            is_modified = original_hash != actual_hash
                            
                    # Check if the content has changed compared to what we want to write
                    content_changed = existing_content != full_content
                except Exception:
                    # If can't read existing file, assume content changed
                    content_changed = True
                    
            if not file_exists or content_changed:
                if file_exists and is_modified:
                    # Record that this file was manually modified
                    self.modified_files.append(str(path))
                    logger.warning(f"File {path} has been manually modified")
                    
                    if not self.force_overwrite and not self.auto_mode:
                        if not self._prompt_yes_no(f"File {path} has been manually modified. Overwrite?"):
                            logger.warning(f"Skipping file: {path}")
                            return False
                elif file_exists and content_changed and not self.force_overwrite and not self.auto_mode:
                    if not self._prompt_yes_no(f"File {path} exists and has different content. Overwrite?"):
                        logger.warning(f"Skipping file: {path}")
                        return False
                        
                with open(path, 'w') as f:
                    f.write(full_content)
                os.chmod(path, mode)
                logger.info(f"Wrote file: {path}")
                self.changed_files.append(str(path))
                return True
            else:
                logger.debug(f"File unchanged, skipping: {path}")
                return True
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            return False
            
    def _prompt_yes_no(self, question):
        """Prompt user for yes/no answer"""
        if self.auto_mode:
            return True
            
        while True:
            answer = input(f"{question} [y/n]: ").lower().strip()
            if answer in ['y', 'yes']:
                return True
            elif answer in ['n', 'no']:
                return False
    
    def _wait_for_device(self, device_name, timeout=30, interval=1):
        """Wait for a network device to appear"""
        logger.info(f"Waiting for device {device_name} to appear...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = subprocess.run(
                ["ip", "link", "show", device_name], 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            if result.returncode == 0:
                logger.info(f"Device {device_name} is ready")
                return True
                
            time.sleep(interval)
            
        logger.error(f"Timed out waiting for device {device_name} after {timeout} seconds")
        return False
                
    def _reload_systemd_networkd(self):
        """Reload systemd-networkd configuration"""
        if self.dry_run:
            logger.info("Would reload systemd-networkd configuration")
            return True
            
        try:
            # Try using networkctl reload first (preferred method)
            logger.info("Reloading networkd configuration using networkctl...")
            result = subprocess.run(["networkctl", "reload"], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            
            # If networkctl reload fails, fall back to systemctl reload
            if result.returncode != 0:
                logger.info("networkctl reload failed, falling back to systemctl reload...")
                subprocess.run(["systemctl", "reload", "systemd-networkd.service"], check=True)
                
            # Give systemd-networkd time to process the new configuration
            logger.info("Waiting for systemd-networkd to process configuration...")
            time.sleep(2)
                
            logger.info("Network configuration reloaded successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload network configuration: {e}")
            
            # As a last resort, try restart if reload fails
            try:
                logger.warning("Reload failed, attempting restart as last resort...")
                subprocess.run(["systemctl", "restart", "systemd-networkd.service"], check=True)
                
                # Give systemd-networkd time to restart and process configuration
                logger.info("Waiting for systemd-networkd to restart...")
                time.sleep(5)
                
                logger.info("Network configuration restarted successfully")
                return True
            except subprocess.CalledProcessError as e2:
                logger.error(f"Failed to restart network configuration: {e2}")
                return False

    def _get_network_addresses(self, veth_network):
        """Get IP addresses for veth pair from network CIDR"""
        try:
            # Parse the network
            network = ipaddress.IPv4Network(veth_network)
            
            # Get the first two usable addresses in the network
            hosts = list(network.hosts())
            
            if len(hosts) < 2:
                logger.error(f"Network {veth_network} does not have enough addresses")
                return None, None
                
            return str(hosts[0]), str(hosts[1])
        except Exception as e:
            logger.error(f"Error getting addresses from network {veth_network}: {e}")
            return None, None
            
    def _apply_wireguard_config(self, vpn):
        """Apply WireGuard VPN configuration"""
        vpn_name = vpn["name"]
        veth_network = vpn["veth_network"]
        routing_table_id = vpn["routing_table_id"]
        
        logger.info(f"Applying WireGuard VPN configuration for {vpn_name}")
        
        # Get IP addresses for veth pair
        host_ip, namespace_ip = self._get_network_addresses(veth_network)
        
        if not host_ip or not namespace_ip:
            logger.error(f"Could not determine IP addresses for network {veth_network}")
            return False
            
        # Create namespace service file
        ns_service_content = f"""[Unit]
Description=Network Namespace for VPN {vpn_name}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/ip netns add ns-{vpn_name}
ExecStop=/usr/bin/ip netns del ns-{vpn_name}

[Install]
WantedBy=multi-user.target
"""
        ns_service_path = SYSTEMD_DIR / f"vpn-ns-{vpn_name}.service"
        self._write_file(ns_service_path, ns_service_content)
        
        # Create veth pair .netdev file
        veth_netdev_content = f"""[NetDev]
Name=v-{vpn_name}-v
Kind=veth

[Peer]
Name=v-{vpn_name}-p
"""
        veth_netdev_path = NETWORKD_DIR / f"10-v-{vpn_name}-veth.netdev"
        self._write_file(veth_netdev_path, veth_netdev_content)
        
        # Create veth parent .network file
        veth_parent_network_content = f"""[Match]
Name=v-{vpn_name}-v

[Network]
Address={host_ip}/30
ConfigureWithoutCarrier=yes
"""
        veth_parent_network_path = NETWORKD_DIR / f"10-v-{vpn_name}-veth.network"
        self._write_file(veth_parent_network_path, veth_parent_network_content)
        
        # Create WireGuard .netdev file
        wg_content = f"""[NetDev]
Name=v-{vpn_name}-w
Kind=wireguard

[WireGuardPeer]
PublicKey={vpn["wireguard"]["peer_public_key"]}
Endpoint={vpn["wireguard"]["endpoint"]}
AllowedIPs=0.0.0.0/0, ::/0
PersistentKeepalive=25
"""

        # Add private key if provided
        if "private_key" in vpn["wireguard"]:
            wg_content = wg_content.replace("[NetDev]", f"""[NetDev]
Name=v-{vpn_name}-w
Kind=wireguard

[WireGuard]
PrivateKey={vpn["wireguard"]["private_key"]}""")
        
        wg_netdev_path = NETWORKD_DIR / f"20-v-{vpn_name}-wireguard.netdev"
        self._write_file(wg_netdev_path, wg_content, mode=0o600)  # Restricted permissions for keys
        
        # Create WireGuard .network file
        wg_network_content = f"""[Match]
Name=v-{vpn_name}-w

[Network]
Address={vpn["wireguard"]["client_ip"]}
ConfigureWithoutCarrier=yes
"""
        
        # Add DNS if provided
        if "dns" in vpn["wireguard"]:
            dns_servers = vpn["wireguard"]["dns"]
            if isinstance(dns_servers, list):
                for dns in dns_servers:
                    wg_network_content += f"DNS={dns}\n"
            else:
                wg_network_content += f"DNS={dns_servers}\n"
                
        wg_network_path = NETWORKD_DIR / f"20-v-{vpn_name}-wireguard.network"
        self._write_file(wg_network_path, wg_network_content)
        
        # Create routing table entry
        table_name = f"{vpn_name}_vpn"
        rt_tables_path = Path("/etc/iproute2/rt_tables.d") / f"{vpn_name}_vpn.conf"
        
        # Ensure rt_tables.d directory exists
        if not self.dry_run:
            os.makedirs("/etc/iproute2/rt_tables.d", exist_ok=True)
            
        rt_tables_content = f"{routing_table_id} {table_name}\n"
        self._write_file(rt_tables_path, rt_tables_content)
        
        # Execute systemd and networking setup
        if not self.dry_run:
            # Check if any of the files for this VPN were manually modified
            vpn_related_files = [
                str(ns_service_path),
                str(veth_netdev_path),
                str(veth_parent_network_path),
                str(wg_netdev_path),
                str(wg_network_path),
                str(rt_tables_path)
            ]
            
            vpn_has_modified_files = any(path in self.modified_files for path in vpn_related_files)
            if vpn_has_modified_files:
                logger.warning(f"VPN {vpn_name} has manually modified files but will still be activated")
            
            # Step 1: Enable and start namespace service
            logger.info(f"Setting up network namespace for {vpn_name}")
            subprocess.run(["systemctl", "enable", "--now", f"vpn-ns-{vpn_name}.service"], check=True)
            
            # Step 2: Reload networkd to create the veth interfaces
            logger.info("Reloading network configuration to create interfaces...")
            self._reload_systemd_networkd()
            
            # Step 3: Wait for veth device to be created by systemd-networkd
            if not self._wait_for_device(f"v-{vpn_name}-p", timeout=30):
                logger.error(f"Failed to create veth device v-{vpn_name}-p")
                return False
                
            # Step 4: Now move peer to namespace
            logger.info(f"Moving peer interface to namespace ns-{vpn_name}...")
            try:
                subprocess.run(["ip", "link", "set", f"v-{vpn_name}-p", "netns", f"ns-{vpn_name}"], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to move interface to namespace: {e}")
                return False
                
            logger.info(f"Configuring network inside namespace for {vpn_name}")
            
            # Get network mask from CIDR notation
            network = ipaddress.IPv4Network(veth_network)
            prefix_len = network.prefixlen
            
            # Step 5: Configure IP in namespace
            try:
                subprocess.run([
                    "ip", "netns", "exec", f"ns-{vpn_name}", 
                    "ip", "addr", "add", f"{namespace_ip}/{prefix_len}", 
                    "dev", f"v-{vpn_name}-p"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to configure IP in namespace: {e}")
                return False
                
            # Step 6: Bring up interface in namespace
            try:
                subprocess.run([
                    "ip", "netns", "exec", f"ns-{vpn_name}", 
                    "ip", "link", "set", "dev", f"v-{vpn_name}-p", "up"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to bring up interface in namespace: {e}")
                return False
                
            # Step 7: Add default route via veth in namespace
            try:
                subprocess.run([
                    "ip", "netns", "exec", f"ns-{vpn_name}", 
                    "ip", "route", "add", "default", "via", f"{host_ip}"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add default route in namespace: {e}")
                return False
        else:
            logger.info(f"Would set up network namespace for {vpn_name}")
            
        # Create rules for routing
        for rule in self._generate_routing_rules(vpn):
            self._apply_routing_rule(rule)
            
        # Record created resources
        self.created_resources.append({
            "type": "namespace",
            "name": f"ns-{vpn_name}",
            "vpn_name": vpn_name
        })
        
        self.created_resources.append({
            "type": "interface",
            "name": f"v-{vpn_name}-v",
            "vpn_name": vpn_name
        })
        
        self.created_resources.append({
            "type": "interface",
            "name": f"v-{vpn_name}-w",
            "vpn_name": vpn_name
        })
        
        self.created_resources.append({
            "type": "routing_table",
            "id": routing_table_id,
            "name": table_name,
            "vpn_name": vpn_name
        })
        
        logger.info(f"Completed WireGuard configuration for {vpn_name}")
        return True
        
    def _generate_routing_rules(self, vpn):
        """Generate routing rules for a VPN connection"""
        vpn_name = vpn["name"]
        routing_table_id = vpn["routing_table_id"]
        rules = []
        
        # Find all clients assigned to this VPN
        assigned_clients = [a for a in self.vpn_clients["assignments"] if a["vpn"] == vpn_name]
        
        # Add rules for each assigned client
        for client in assigned_clients:
            client_id = client["client_id"]
            
            # Validate client ID format
            if not self._validate_client_id(client_id):
                logger.warning(f"Invalid client ID format: {client_id}, skipping")
                continue
                
            # Add routing rule
            rule = {
                "type": "from_client",
                "client_id": client_id,
                "routing_table_id": routing_table_id,
                "vpn_name": vpn_name
            }
            rules.append(rule)
            
        return rules
        
    def _validate_client_id(self, client_id):
        """Validate client ID format (IP address or MAC address)"""
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(client_id)
            return True
        except ValueError:
            pass
            
        # Check if it's a valid MAC address
        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_id):
            return True
            
        return False
        
    def _apply_routing_rule(self, rule):
        """Apply a routing rule"""
        if rule["type"] == "from_client":
            client_id = rule["client_id"]
            routing_table_id = rule["routing_table_id"]
            vpn_name = rule["vpn_name"]
            
            # Check if it's an IP or MAC
            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_id):
                # MAC address - create a networkd rule file
                rule_content = f"""[Match]
MACAddress={client_id}

[Network]
IPForward=yes

[RoutingPolicyRule]
Table={routing_table_id}
Priority=100
"""
                rule_path = NETWORKD_DIR / f"50-{vpn_name}-client-{client_id.replace(':', '-')}.network"
                self._write_file(rule_path, rule_content)
                
                self.created_resources.append({
                    "type": "networkd_rule",
                    "path": str(rule_path),
                    "vpn_name": vpn_name,
                    "client_id": client_id
                })
            else:
                # IP address - use ip rule
                if not self.dry_run:
                    try:
                        # Delete any existing rules for this IP/table
                        subprocess.run([
                            "ip", "rule", "del", 
                            "from", client_id, 
                            "lookup", str(routing_table_id)
                        ], stderr=subprocess.DEVNULL)
                    except Exception:
                        # Ignore errors if rule doesn't exist
                        pass
                        
                    # Add the new rule
                    subprocess.run([
                        "ip", "rule", "add", 
                        "from", client_id, 
                        "lookup", str(routing_table_id),
                        "prio", "100"
                    ], check=True)
                    
                    logger.info(f"Added routing rule: from {client_id} lookup {routing_table_id}")
                else:
                    logger.info(f"Would add routing rule: from {client_id} lookup {routing_table_id}")
                    
                self.created_resources.append({
                    "type": "ip_rule",
                    "from": client_id,
                    "table_id": routing_table_id,
                    "vpn_name": vpn_name
                })

    def _is_managed_file(self, file_path):
        """Check if a file is managed by vpn-router by examining metadata"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Check for our metadata header
            if "# Generated by vpn-apply.py" in content and "# DO NOT EDIT - This file is managed by vpn-router" in content:
                return True
                
            return False
        except Exception:
            return False
    
    def _is_file_manually_modified(self, file_path):
        """Check if a managed file was manually modified by comparing hash"""
        try:
            # Extract the stored hash from file metadata
            stored_hash = self._extract_hash_from_file(file_path)
            
            if stored_hash:
                # Read the file content
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Extract content without metadata
                content_without_metadata = self._extract_content_without_metadata(content)
                
                # Calculate actual hash of content
                actual_hash = self._calculate_content_hash(content_without_metadata)
                
                # If hashes don't match, file was modified
                return stored_hash != actual_hash
                
            # If no hash found but file is managed, assume it's modified
            return self._is_managed_file(file_path)
        except Exception:
            # If any error occurs, assume file was not modified
            return False

    def _check_vpn_files_modified(self, vpn_name):
        """
        Check if any files related to a specific VPN have been manually modified
        
        Args:
            vpn_name: Name of the VPN to check
            
        Returns:
            bool: True if any files were modified, False otherwise
            list: List of modified file paths
        """
        modified_files = []
        
        # Define patterns for VPN related files
        patterns = [
            f"vpn-ns-{vpn_name}.service",
            f"10-v-{vpn_name}-*.netdev",
            f"10-v-{vpn_name}-*.network",
            f"20-v-{vpn_name}-*.netdev",
            f"20-v-{vpn_name}-*.network",
            f"50-{vpn_name}-client-*.network",
            f"{vpn_name}_vpn.conf"
        ]
        
        # Check SYSTEMD_DIR for service files
        for pattern in [f"vpn-ns-{vpn_name}.service"]:
            for file_path in SYSTEMD_DIR.glob(pattern):
                if self._is_managed_file(file_path) and self._is_file_manually_modified(file_path):
                    modified_files.append(str(file_path))
        
        # Check NETWORKD_DIR for network files
        for pattern in [f"10-v-{vpn_name}-*.netdev", f"10-v-{vpn_name}-*.network", 
                      f"20-v-{vpn_name}-*.netdev", f"20-v-{vpn_name}-*.network",
                      f"50-{vpn_name}-client-*.network"]:
            for file_path in NETWORKD_DIR.glob(pattern):
                if self._is_managed_file(file_path) and self._is_file_manually_modified(file_path):
                    modified_files.append(str(file_path))
                    
        # Check rt_tables.d for routing table files
        rt_tables_d_path = Path("/etc/iproute2/rt_tables.d")
        if rt_tables_d_path.exists():
            for file_path in rt_tables_d_path.glob(f"{vpn_name}_vpn.conf"):
                if self._is_managed_file(file_path) and self._is_file_manually_modified(file_path):
                    modified_files.append(str(file_path))
                    
        return len(modified_files) > 0, modified_files

    def _check_orphaned_resources(self):
        """
        Check for orphaned resources and clean them up
        
        Returns:
            Dictionary with counts of cleaned resources by type
        """
        if self.dry_run:
            logger.info("=== DRY RUN MODE - Would check for orphaned resources ===")
        else:
            logger.info("Checking for orphaned resources...")
        
        # Reset cleaned resources counter
        self.cleaned_resources = {
            "namespaces": 0,
            "interfaces": 0,
            "routing_tables": 0,
            "routing_rules": 0,
            "services": 0,
            "files": 0
        }
        
        # Get current active resources
        active_vpn_names = self._get_active_vpns()
        
        # Get all defined VPN names for detecting truly orphaned resources
        # (not in our config at all)
        defined_vpn_names = {vpn["name"] for vpn in self.vpn_definitions["vpn_connections"]}
        
        # Fix for the isdigit error - handle both string and int types for routing_table_id
        active_vpn_table_ids = set()
        for vpn in self.vpn_definitions["vpn_connections"]:
            if "routing_table_id" in vpn and vpn["name"] in active_vpn_names:
                table_id = vpn["routing_table_id"]
                # Convert to int if it's a string and can be converted
                if isinstance(table_id, str):
                    if table_id.isdigit():
                        active_vpn_table_ids.add(int(table_id))
                else:
                    # If it's already an int or another numeric type
                    active_vpn_table_ids.add(int(table_id))
        
        # Define routing table range
        min_table_id = self.vpn_definitions["system_config"]["routing_table_id_range"]["min"]
        max_table_id = self.vpn_definitions["system_config"]["routing_table_id_range"]["max"]
        network_prefix = self.vpn_definitions["system_config"]["veth_network_range"]["prefix"]
        
        # Clean up routing tables in rt_tables.d
        rt_tables_d_path = Path("/etc/iproute2/rt_tables.d")
        if rt_tables_d_path.exists():
            logger.info("Checking for orphaned routing tables in rt_tables.d...")
            
            # First, scan all rt_tables.d files to identify orphaned tables
            orphaned_files = []
            
            for file_path in rt_tables_d_path.glob("*.conf"):
                try:
                    # Extract VPN name from filename
                    file_name = file_path.name
                    if "_vpn.conf" in file_name:
                        vpn_name = file_name.replace("_vpn.conf", "")
                        
                        # If VPN is defined in config but not active, or completely unknown
                        if vpn_name not in active_vpn_names:
                            # Check if this is a managed file
                            is_managed = self._is_managed_file(file_path)
                            
                            # Check if the file was manually modified
                            is_modified = is_managed and self._is_file_manually_modified(file_path)
                            
                            if is_managed and is_modified:
                                # Log but don't clean up
                                logger.warning(f"Orphaned routing table file {file_path} was manually modified, not removing")
                            else:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                
                                # Extract table ID and name
                                content_without_metadata = self._extract_content_without_metadata(content) if is_managed else content
                                match = re.match(r"^\s*(\d+)\s+(\S+)", content_without_metadata.strip())
                                
                                if match:
                                    table_id = int(match.group(1))
                                    table_name = match.group(2)
                                    
                                    logger.info(f"Found orphaned routing table: {table_id} ({table_name}) in {file_path}")
                                    
                                    if not self.dry_run:
                                        try:
                                            os.remove(file_path)
                                            self.cleaned_resources["routing_tables"] += 1
                                            logger.info(f"Removed orphaned routing table file: {file_path}")
                                        except Exception as e:
                                            logger.error(f"Failed to remove routing table file {file_path}: {e}")
                                    else:
                                        logger.info(f"Would remove orphaned routing table file: {file_path}")
                                        self.cleaned_resources["routing_tables"] += 1
                                        
                except Exception as e:
                    logger.error(f"Error processing routing table file {file_path}: {e}")
        
        # Clean up routing tables in main rt_tables file
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        if rt_tables_path.exists():
            try:
                logger.info("Checking for orphaned routing tables in main rt_tables file...")
                
                with open(rt_tables_path, 'r') as f:
                    lines = f.readlines()
                
                new_lines = []
                modified = False
                
                for line in lines:
                    if line.strip() and not line.strip().startswith("#"):
                        match = re.match(r"^\s*(\d+)\s+(\S+)", line)
                        if match:
                            table_id = int(match.group(1))
                            table_name = match.group(2)
                            
                            # Check if it's in our range and not active
                            if (min_table_id <= table_id <= max_table_id and 
                                table_id not in active_vpn_table_ids):
                                
                                logger.info(f"Found orphaned routing table in main rt_tables: {table_id} ({table_name})")
                                
                                if not self.dry_run:
                                    modified = True
                                    self.cleaned_resources["routing_tables"] += 1
                                    logger.info(f"Removed orphaned routing table from main rt_tables: {table_id} ({table_name})")
                                    continue
                                else:
                                    logger.info(f"Would remove orphaned routing table from main rt_tables: {table_id} ({table_name})")
                                    self.cleaned_resources["routing_tables"] += 1
                    
                    new_lines.append(line)
                
                if modified:
                    with open(rt_tables_path, 'w') as f:
                        f.writelines(new_lines)
            except Exception as e:
                logger.error(f"Error cleaning main rt_tables file: {e}")
        
        # Clean up routing rules
        try:
            logger.info("Checking for orphaned routing rules...")
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
                                table_id not in active_vpn_table_ids):
                                
                                # Extract from clause if exists
                                from_match = re.search(r"from\s+([0-9./]+)", line)
                                from_ip = from_match.group(1) if from_match else None
                                
                                # Extract priority
                                priority_match = re.search(r"^(\d+):", line)
                                priority = priority_match.group(1) if priority_match else None
                                
                                cmd = ["ip", "rule", "del"]
                                
                                if from_ip:
                                    cmd.extend(["from", from_ip])
                                    
                                cmd.extend(["lookup", str(table_id)])
                                
                                if priority:
                                    cmd.extend(["prio", priority])
                                
                                logger.info(f"Found orphaned routing rule: {' '.join(cmd)}")
                                
                                if not self.dry_run:
                                    try:
                                        subprocess.run(cmd, check=True)
                                        self.cleaned_resources["routing_rules"] += 1
                                        logger.info(f"Removed orphaned routing rule: {' '.join(cmd)}")
                                    except subprocess.CalledProcessError as e:
                                        logger.error(f"Failed to remove routing rule: {e}")
                                else:
                                    logger.info(f"Would remove orphaned routing rule: {' '.join(cmd)}")
                                    self.cleaned_resources["routing_rules"] += 1
        except Exception as e:
            logger.error(f"Error cleaning routing rules: {e}")
        
        # Clean up networkd files
        try:
            logger.info("Checking for orphaned networkd files...")
            
            # First, gather all active VPN-related interface names
            active_interface_patterns = []
            for vpn_name in active_vpn_names:
                active_interface_patterns.extend([
                    f"10-v-{vpn_name}-*.netdev", 
                    f"10-v-{vpn_name}-*.network", 
                    f"20-v-{vpn_name}-*.netdev", 
                    f"20-v-{vpn_name}-*.network", 
                    f"50-{vpn_name}-client-*.network"
                ])
            
            # Process all VPN-related network files
            for file_path in NETWORKD_DIR.glob("[0-9]*-v-*-*.netdev"):
                self._check_and_clean_networkd_file(file_path, active_vpn_names, defined_vpn_names)
                
            for file_path in NETWORKD_DIR.glob("[0-9]*-v-*-*.network"):
                self._check_and_clean_networkd_file(file_path, active_vpn_names, defined_vpn_names)
                
            for file_path in NETWORKD_DIR.glob("50-*-client-*.network"):
                self._check_and_clean_networkd_file(file_path, active_vpn_names, defined_vpn_names)
                
        except Exception as e:
            logger.error(f"Error cleaning networkd files: {e}")
        
        # Clean up systemd service files
        try:
            logger.info("Checking for orphaned systemd service files...")
            
            for service_path in SYSTEMD_DIR.glob("vpn-ns-*.service"):
                # Extract VPN name from service file
                vpn_name = service_path.name.split("vpn-ns-")[1].split(".")[0]
                
                if vpn_name not in active_vpn_names:
                    # Check if this is a managed file
                    is_managed = self._is_managed_file(service_path)
                    
                    # Check if the file was manually modified
                    is_modified = is_managed and self._is_file_manually_modified(service_path)
                    
                    if is_managed and is_modified:
                        logger.warning(f"Orphaned service file {service_path} was manually modified, not removing")
                    else:
                        logger.info(f"Found orphaned service: {service_path}")
                        
                        if not self.dry_run:
                            try:
                                # Disable and stop the service
                                subprocess.run(["systemctl", "disable", "--now", service_path.name], 
                                             stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                                
                                # Remove the service file
                                os.remove(service_path)
                                self.cleaned_resources["services"] += 1
                                logger.info(f"Removed orphaned service: {service_path}")
                            except Exception as e:
                                logger.error(f"Failed to remove service {service_path}: {e}")
                        else:
                            logger.info(f"Would remove orphaned service: {service_path}")
                            self.cleaned_resources["services"] += 1
        except Exception as e:
            logger.error(f"Error cleaning systemd services: {e}")
        
        # Clean up network namespaces
        try:
            logger.info("Checking for orphaned network namespaces...")
            
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
                    if vpn_name not in active_vpn_names:
                        logger.info(f"Found orphaned namespace: {ns_name}")
                        
                        if not self.dry_run:
                            try:
                                subprocess.run(["ip", "netns", "del", ns_name], check=True)
                                self.cleaned_resources["namespaces"] += 1
                                logger.info(f"Removed orphaned namespace: {ns_name}")
                            except subprocess.CalledProcessError as e:
                                logger.error(f"Failed to remove namespace {ns_name}: {e}")
                        else:
                            logger.info(f"Would remove orphaned namespace: {ns_name}")
                            self.cleaned_resources["namespaces"] += 1
        except Exception as e:
            logger.error(f"Error cleaning network namespaces: {e}")
        
        # Clean up network interfaces
        try:
            logger.info("Checking for orphaned network interfaces...")
            
            # Look for interfaces with our naming pattern
            if_pattern = re.compile(r"\d+:\s+(v-([a-zA-Z0-9_-]+)-[wvp])[@:]")
            if_output = subprocess.run(["ip", "link", "show"], 
                                     capture_output=True, text=True).stdout
            
            for line in if_output.splitlines():
                match = if_pattern.search(line)
                if match:
                    if_name = match.group(1)
                    vpn_name = match.group(2)
                    
                    # Check if VPN is active
                    if vpn_name not in active_vpn_names:
                        logger.info(f"Found orphaned interface: {if_name}")
                        
                        if not self.dry_run:
                            try:
                                subprocess.run(["ip", "link", "del", if_name], check=True)
                                self.cleaned_resources["interfaces"] += 1
                                logger.info(f"Removed orphaned interface: {if_name}")
                            except subprocess.CalledProcessError as e:
                                logger.error(f"Failed to remove interface {if_name}: {e}")
                        else:
                            logger.info(f"Would remove orphaned interface: {if_name}")
                            self.cleaned_resources["interfaces"] += 1
        except Exception as e:
            logger.error(f"Error cleaning network interfaces: {e}")
        
        if not self.dry_run:
            logger.info(f"Cleaned up resources: {self.cleaned_resources}")
        else:
            logger.info(f"Would clean up resources: {self.cleaned_resources}")
            
        return self.cleaned_resources
        
    def _check_and_clean_networkd_file(self, file_path, active_vpn_names, defined_vpn_names):
        """Helper method to check and clean a networkd file"""
        # Extract VPN name from the file name
        if "-v-" in file_path.name:
            # Format v-{vpn_name}-* for veth and wireguard devices
            name_parts = file_path.name.split("-v-")
            if len(name_parts) > 1:
                vpn_parts = name_parts[1].split("-", 1)
                if len(vpn_parts) > 0:
                    vpn_name = vpn_parts[0]
                    
                    if vpn_name not in active_vpn_names:
                        # Check if this is a managed file
                        is_managed = self._is_managed_file(file_path)
                        
                        # Check if the file was manually modified
                        is_modified = is_managed and self._is_file_manually_modified(file_path)
                        
                        if is_managed and is_modified:
                            # For VPNs in our config but not active, we check for manual modifications
                            if vpn_name in defined_vpn_names:
                                logger.warning(f"Orphaned networkd file {file_path} was manually modified, not removing")
                            else:
                                # For completely unknown VPNs, we still clean up
                                self._remove_networkd_file(file_path)
                        else:
                            # Not modified or not managed by us, remove it
                            self._remove_networkd_file(file_path)
        elif "client-" in file_path.name:
            # Format 50-{vpn_name}-client-*
            name_parts = file_path.name.split("-client-")
            if len(name_parts) > 0:
                vpn_parts = name_parts[0].split("-", 1)
                if len(vpn_parts) > 1:
                    vpn_name = vpn_parts[1]
                    
                    if vpn_name not in active_vpn_names:
                        # Check if this is a managed file
                        is_managed = self._is_managed_file(file_path)
                        
                        # Check if the file was manually modified
                        is_modified = is_managed and self._is_file_manually_modified(file_path)
                        
                        if is_managed and is_modified:
                            # For VPNs in our config but not active, we check for manual modifications
                            if vpn_name in defined_vpn_names:
                                logger.warning(f"Orphaned networkd client rule file {file_path} was manually modified, not removing")
                            else:
                                # For completely unknown VPNs, we still clean up
                                self._remove_networkd_file(file_path)
                        else:
                            # Not modified or not managed by us, remove it
                            self._remove_networkd_file(file_path)
                            
    def _remove_networkd_file(self, file_path):
        """Helper method to remove a networkd file"""
        logger.info(f"Found orphaned networkd file: {file_path}")
        
        if not self.dry_run:
            try:
                os.remove(file_path)
                self.cleaned_resources["files"] += 1
                logger.info(f"Removed orphaned networkd file: {file_path}")
            except Exception as e:
                logger.error(f"Failed to remove file {file_path}: {e}")
        else:
            logger.info(f"Would remove orphaned networkd file: {file_path}")
            self.cleaned_resources["files"] += 1

    def apply_configuration(self):
        """Apply the VPN router configuration"""
        if self.dry_run:
            logger.info("=== DRY RUN MODE - No changes will be applied ===")
            
        # First, check for and clean orphaned resources
        self._check_orphaned_resources()
            
        logger.info("Applying VPN router configuration...")
        
        # Reset tracking variables
        self.changed_files = []
        self.created_resources = []
        
        # Get active VPNs (with at least one client assigned)
        active_vpns = self._get_active_vpns()
        
        if not active_vpns:
            logger.info("No active VPN connections found (no clients assigned)")
            if self.dry_run:
                logger.info("=== DRY RUN COMPLETED - No changes would be applied ===")
            return
            
        # Apply each active VPN configuration
        for vpn in self.vpn_definitions["vpn_connections"]:
            if vpn["name"] in active_vpns:
                # Check if any files for this VPN were manually modified
                is_modified, modified_files = self._check_vpn_files_modified(vpn["name"])
                
                if is_modified:
                    logger.warning(f"VPN {vpn['name']} has manually modified files:")
                    for file in modified_files:
                        logger.warning(f"  - {file}")
                    logger.warning(f"Will still attempt to activate VPN {vpn['name']}")
                    
                # Apply VPN configuration
                self._apply_wireguard_config(vpn)
            else:
                logger.info(f"Skipping VPN {vpn['name']} - no clients assigned")
                
        # Reload systemd-networkd if needed and not in dry run
        if self.changed_files and not self.dry_run:
            # Check if any network or netdev files were changed
            network_files_changed = any(
                f.endswith(".network") or f.endswith(".netdev") 
                for f in self.changed_files
            )
            
            if network_files_changed:
                logger.info("Network configuration files changed, reloading network configuration...")
                self._reload_systemd_networkd()
                
        if self.dry_run:
            logger.info("=== DRY RUN COMPLETED - No changes were applied ===")
        else:
            logger.info("VPN router configuration applied successfully")
            
        # Return summary of changes
        return {
            "dry_run": self.dry_run,
            "changed_files": self.changed_files,
            "created_resources": self.created_resources,
            "cleaned_resources": self.cleaned_resources
        }


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VPN Policy Router")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--auto", action="store_true", help="Run in automatic mode without user prompts")
    parser.add_argument("--force-overwrite", action="store_true", help="Force overwrite of modified files")
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
        force_overwrite=args.force_overwrite
    )
    
    router.apply_configuration()


if __name__ == "__main__":
    main()
