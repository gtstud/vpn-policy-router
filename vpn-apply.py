#!/usr/bin/env python3
"""
VPN Policy Router Configuration Apply Script
This script applies the VPN router configuration from JSON definitions.
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
import socket
from pathlib import Path
from datetime import datetime, timezone

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('vpn-router')

CONFIG_DIR = Path("/etc/vpn-router")
NETWORKD_DIR = Path("/etc/systemd/network")
SYSTEMD_DIR = Path("/etc/systemd/system")
RT_TABLES_DIR = Path("/etc/iproute2/rt_tables.d")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
GENERATOR_NAME = "vpn-apply.py"
GENERATOR_VERSION = "4.0"

class VPNRouter:
    """Manages the entire lifecycle of VPN configurations."""

    def __init__(self, dry_run=False, auto_mode=False):
        self.dry_run = dry_run
        self.auto_mode = auto_mode
        self.changed_files = set()
        self.vpn_definitions = self._load_json(VPN_DEFINITIONS_PATH)
        self.vpn_clients = self._load_json(VPN_CLIENTS_PATH)
        self._validate_config()

    def _load_json(self, path):
        if path.exists():
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {path}: {e}")
                sys.exit(1)
        
        logger.warning(f"Config file not found: {path}. Creating a default.")
        if path == VPN_DEFINITIONS_PATH:
            template = {
                "system_config": {
                    "firewalld": {"zone_lan": "trusted", "zone_vpn": "trusted"},
                    "lan_network_files": {},
                    "nat": {"lan_subnets": ["192.168.0.0/16"]}
                },
                "vpn_connections": []
            }
        else:
            template = {"assignments": []}
        
        if not self.dry_run:
            self._write_file(path, json.dumps(template, indent=2), mode=0o600, owner='root', group='root', add_header=False)
        return template

    def _validate_config(self):
        logger.info("Validating configuration...")

        # --- Validate vpn-definitions.json ---
        if "system_config" not in self.vpn_definitions:
            raise ValueError("Missing 'system_config' in vpn-definitions.json")
        if "firewalld" not in self.vpn_definitions["system_config"] or "zone_vpn" not in self.vpn_definitions["system_config"]["firewalld"]:
            raise ValueError("Missing 'firewalld.zone_vpn' in system_config")
        if "lan_network_files" not in self.vpn_definitions["system_config"]:
            raise ValueError("Missing 'lan_network_files' in system_config")

        # The nftables config is no longer used from the host
        if "nftables" in self.vpn_definitions["system_config"]:
            logger.warning("The 'nftables' section in system_config is no longer used and can be removed.")

        vpn_conns = self.vpn_definitions.get("vpn_connections", [])
        seen_names = set()
        seen_table_ids = set()
        for vpn in vpn_conns:
            if vpn['name'] in seen_names: raise ValueError(f"Duplicate VPN name found: {vpn['name']}")
            seen_names.add(vpn['name'])

            if vpn['routing_table_id'] in seen_table_ids: raise ValueError(f"Duplicate routing_table_id: {vpn['routing_table_id']}")
            seen_table_ids.add(vpn['routing_table_id'])

            try:
                ipaddress.ip_network(vpn['veth_network'])
                ipaddress.ip_interface(vpn['vpn_assigned_ip']) # Use ip_interface for host IPs
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation in VPN '{vpn['name']}': {e}")

            if "router_lan_interface" not in vpn:
                raise ValueError(f"VPN '{vpn['name']}' is missing 'router_lan_interface' definition.")

            # A simple regex for WireGuard keys (44-char Base64)
            key_regex = re.compile(r'^[A-Za-z0-9+/]{43}=$')
            if not key_regex.match(vpn['client_private_key']) or not key_regex.match(vpn['peer_public_key']):
                raise ValueError(f"Invalid WireGuard key format in VPN '{vpn['name']}'")

        # --- Validate vpn-clients.json ---
        client_assignments = self.vpn_clients.get("assignments", [])
        seen_display_names = set()
        for client in client_assignments:
            if client['display_name'] in seen_display_names: raise ValueError(f"Duplicate client display_name: {client['display_name']}")
            seen_display_names.add(client['display_name'])

            if not client.get('hostname') and not client.get('ip_address'):
                raise ValueError(f"Client '{client['display_name']}' must have either a hostname or an IP address.")
            if client.get('hostname') and client.get('ip_address'):
                raise ValueError(f"Client '{client['display_name']}' cannot have both a hostname and an IP address.")

            assigned_vpn = client.get('assigned_vpn')
            if assigned_vpn and assigned_vpn not in seen_names:
                raise ValueError(f"Client '{client['display_name']}' is assigned to a non-existent VPN: '{assigned_vpn}'")

        logger.info("Configuration validation successful.")

    def _run_cmd(self, cmd, check=True):
        logger.debug(f"Running command: {' '.join(cmd)}")
        if self.dry_run:
            logger.info(f"DRY RUN: Would run: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        try:
            return subprocess.run(cmd, check=check, capture_output=True, text=True)
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}. Is it installed?")
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}\n{e.stderr}")
            return None

    def _write_file(self, path, content, mode=0o644, owner=None, group=None, add_header=True):
        path = Path(path)

        if path.suffix == '.json':
            add_header = False

        if add_header:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            header = f"# Generated by {GENERATOR_NAME} v{GENERATOR_VERSION}\n# HASH: {content_hash}\n"
            full_content = header + content
        else:
            full_content = content

        # Check if file needs updating
        if path.exists():
            try:
                if path.read_text() == full_content and path.stat().st_mode & 0o777 == mode:
                    # More complex check for owner/group needed if we want to be fully idempotent
                    return
            except IOError:
                pass

        logger.info(f"Writing configuration to {path}")
        self.changed_files.add(str(path))

        if not self.dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(full_content)
            path.chmod(mode)
            if owner or group:
                try:
                    shutil.chown(path, user=owner, group=group)
                except Exception as e:
                    logger.error(f"Failed to set ownership on {path}: {e}")

    def _get_network_addresses(self, cidr):
        try:
            net = ipaddress.ip_network(cidr)
            if net.prefixlen != 30: raise ValueError("veth_network must be a /30 subnet.")
            hosts = list(net.hosts())
            return str(hosts[0]), str(hosts[1])
        except ValueError as e:
            logger.error(f"Invalid CIDR '{cidr}': {e}")
            return None, None

    def _get_vpn_resource_files(self, vpn_name):
        host_veth = f"v-{vpn_name}-v"
        ns_veth = f"v-{vpn_name}-p"
        wg_if = f"v-{vpn_name}-w"

        files = [
            SYSTEMD_DIR / f"vpn-ns-{vpn_name}.service",
            NETWORKD_DIR / f"10-{host_veth}.netdev",
            NETWORKD_DIR / f"10-{host_veth}.network",
            NETWORKD_DIR / f"20-{wg_if}.netdev",
            NETWORKD_DIR / f"30-{wg_if}.network",
            NETWORKD_DIR / f"30-{ns_veth}.network",
            RT_TABLES_DIR / f"99-vpn-router-{vpn_name}.conf",
        ]

        # Find associated client drop-in files
        vpn_config = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
        if not vpn_config:
            return files

        lan_if = vpn_config.get("router_lan_interface")
        if not lan_if:
            return files

        dropin_dir = NETWORKD_DIR / f"{lan_if}.network.d"
        if not dropin_dir.exists():
            return files

        for client in self.vpn_clients.get("assignments", []):
            if client.get("assigned_vpn") == vpn_name:
                ip = client.get("ip_address")
                if not ip and client.get("hostname"):
                    try:
                        ip = socket.gethostbyname(client["hostname"])
                    except socket.gaierror:
                        continue

                if ip:
                    filename = f"10-vpn-router-{ip.replace('.', '-')}.conf"
                    files.append(dropin_dir / filename)

        return files

    def _is_file_manually_modified(self, file_path):
        if not file_path.exists(): return False
        try:
            content = file_path.read_text()
            match = re.search(r'# HASH: ([a-f0-9]{64})', content)
            if not match: return True
            stored_hash = match.group(1)
            header, _, body = content.partition('\n# HASH: ')
            body = body.split('\n', 1)[1]
            actual_hash = hashlib.sha256(body.encode()).hexdigest()
            return stored_hash != actual_hash
        except Exception:
            return True

    def _prune_expired_clients(self):
        now = datetime.now(timezone.utc)
        original_count = len(self.vpn_clients["assignments"])
        active_assignments = []
        for client in self.vpn_clients["assignments"]:
            expiry_str = client.get("assignment_expiry")
            if expiry_str:
                try:
                    if datetime.fromisoformat(expiry_str.replace("Z", "+00:00")) < now:
                        logger.info(f"Pruning expired client: {client['display_name']}")
                        continue
                except (ValueError, TypeError):
                    logger.warning(f"Invalid expiry format for client '{client.get('display_name', 'N/A')}'")
            active_assignments.append(client)
        if len(active_assignments) < original_count:
            self.vpn_clients["assignments"] = active_assignments
            self._write_file(VPN_CLIENTS_PATH, json.dumps(self.vpn_clients, indent=2), mode=0o600, owner='root', group='root', add_header=False)

    def _manage_timer(self, enable: bool):
        self._run_cmd(["systemctl", "enable" if enable else "disable", "--now", "vpn-router.timer"], check=False)

    def _resolve_assignments(self):
        resolved_map = {}
        vpn_names = {vpn['name'] for vpn in self.vpn_definitions.get("vpn_connections", [])}
        for client in self.vpn_clients.get("assignments", []):
            vpn_name = client.get("assigned_vpn")
            if not vpn_name: continue
            if vpn_name not in vpn_names:
                logger.warning(f"Client '{client['display_name']}' is assigned to a non-existent VPN: '{vpn_name}'")
                continue
            ip_address = client.get("ip_address")
            if not ip_address and client.get("hostname"):
                try:
                    ip_address = socket.gethostbyname(client["hostname"])
                except socket.gaierror:
                    logger.warning(f"Could not resolve hostname '{client['hostname']}'")
                    continue
            if ip_address:
                resolved_map.setdefault(vpn_name, []).append(ip_address)
        return resolved_map

    def _wait_for_interface(self, if_name, timeout=10):
        logger.debug(f"Waiting for interface {if_name} to appear...")
        for _ in range(timeout):
            result = self._run_cmd(['ip', 'link', 'show', if_name], check=False)
            if result and result.returncode == 0:
                logger.debug(f"Interface {if_name} found.")
                return True
            time.sleep(1)
        logger.error(f"Timeout waiting for interface {if_name} to appear.")
        return False

    def _apply_vpn_config(self, vpn):
        vpn_name = vpn["name"]
        ns_name = f"ns-{vpn_name}"
        host_veth, ns_veth = f"v-{vpn_name}-v", f"v-{vpn_name}-p"
        wg_if = f"v-{vpn_name}-w"
        host_ip, ns_ip = self._get_network_addresses(vpn["veth_network"])

        logger.info(f"Applying network configuration for VPN '{vpn_name}'...")
        # Systemd service file
        self._write_file(SYSTEMD_DIR / f"vpn-ns-{vpn_name}.service", f"[Unit]\nDescription=NetNS for {vpn_name}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/ip netns add {ns_name}\nExecStop=/usr/bin/ip netns del {ns_name}\n\n[Install]\nWantedBy=multi-user.target", mode=0o644, owner='root', group='root')

        # Networkd files
        network_files_owner = 'root'
        network_files_group = 'systemd-network'
        network_files_mode = 0o640

        self._write_file(NETWORKD_DIR / f"10-{host_veth}.netdev", f"[NetDev]\nName={host_veth}\nKind=veth\n[Peer]\nName={ns_veth}", mode=network_files_mode, owner=network_files_owner, group=network_files_group)
        self._write_file(NETWORKD_DIR / f"10-{host_veth}.network", f"[Match]\nName={host_veth}\n[Network]\nAddress={host_ip}/30", mode=network_files_mode, owner=network_files_owner, group=network_files_group)
        self._write_file(NETWORKD_DIR / f"30-{ns_veth}.network", f"[Match]\nName={ns_veth}\n[Network]\nAddress={ns_ip}/30", mode=network_files_mode, owner=network_files_owner, group=network_files_group)
        self._write_file(NETWORKD_DIR / f"20-{wg_if}.netdev", f"[NetDev]\nName={wg_if}\nKind=wireguard\n[WireGuard]\nPrivateKey={vpn['client_private_key']}", mode=network_files_mode, owner=network_files_owner, group=network_files_group)
        self._write_file(NETWORKD_DIR / f"30-{wg_if}.network", f"[Match]\nName={wg_if}\n[Network]\nAddress={vpn['vpn_assigned_ip']}\nDefaultRouteOnDevice=true\n[WireGuardPeer]\nPublicKey={vpn['peer_public_key']}\nEndpoint={vpn['peer_endpoint']}\nAllowedIPs=0.0.0.0/0", mode=network_files_mode, owner=network_files_owner, group=network_files_group)

        self._run_cmd(["systemctl", "daemon-reload"])
        self._run_cmd(["systemctl", "enable", "--now", f"vpn-ns-{vpn_name}.service"])
        self._run_cmd(["networkctl", "reload"])

        # Wait for interfaces to be created before moving them
        if self._wait_for_interface(host_veth) and self._wait_for_interface(wg_if):
            self._run_cmd(["ip", "link", "set", wg_if, "netns", ns_name], check=False)
            self._run_cmd(["ip", "link", "set", ns_veth, "netns", ns_name], check=False)
            self._run_cmd(["ip", "netns", "exec", ns_name, "systemctl", "restart", "systemd-networkd"], check=False)

            # Setup NAT inside the namespace
            logger.info(f"Setting up NAT inside namespace {ns_name}")
            self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'table', 'ip', 'nat'], check=False)
            self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'chain', 'ip', 'nat', 'POSTROUTING', '{ type nat hook postrouting priority 100 ; }'], check=False)
            self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'rule', 'ip', 'nat', 'POSTROUTING', 'oifname', wg_if, 'masquerade'], check=False)
        else:
            logger.error(f"Could not create interfaces for VPN '{vpn_name}'. Aborting configuration.")

    def _sync_routing_rules(self, resolved_clients_map):
        logger.info("Synchronizing declarative routing rules...")
        # Group clients by the LAN interface they are on
        clients_by_interface = {}
        for vpn_name, ips in resolved_clients_map.items():
            vpn = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
            if not vpn:
                continue

            lan_if = vpn.get("router_lan_interface")
            if not lan_if:
                logger.warning(f"VPN '{vpn_name}' does not have a 'router_lan_interface' defined. Skipping routing rule.")
                continue

            for ip in ips:
                clients_by_interface.setdefault(lan_if, []).append({'ip': ip, 'table': vpn['routing_table_id']})

        # For each LAN interface, sync the drop-in files
        lan_network_files = self.vpn_definitions["system_config"]["lan_network_files"]
        for lan_if, clients in clients_by_interface.items():
            network_file = lan_network_files.get(lan_if)
            if not network_file:
                logger.warning(f"No .network file defined for LAN interface '{lan_if}' in 'lan_network_files'. Cannot create routing rules.")
                continue

            dropin_dir = NETWORKD_DIR / f"{network_file}.d"

            # Get desired state
            desired_files = {f"10-vpn-router-{client['ip'].replace('.', '-')}.conf" for client in clients}

            # Get current state
            if dropin_dir.exists():
                current_files = {f.name for f in dropin_dir.glob("10-vpn-router-*.conf")}
            else:
                current_files = set()

            # Create missing drop-ins
            for client in clients:
                ip = client['ip']
                table_id = client['table']
                filename = f"10-vpn-router-{ip.replace('.', '-')}.conf"
                if filename not in current_files:
                    logger.info(f"Creating routing rule for {ip} via {lan_if}")
                    content = f"[RoutingPolicyRule]\nFrom={ip}\nTable={table_id}\n"
                    self._write_file(dropin_dir / filename, content, mode=0o640, owner='root', group='systemd-network')

            # Remove orphaned drop-ins
            for filename in (current_files - desired_files):
                logger.info(f"Removing orphaned routing rule file: {filename}")
                if not self.dry_run:
                    (dropin_dir / filename).unlink()
                self.changed_files.add("networkd_config")

        # Cleanup: remove all our drop-in files for interfaces that no longer have clients
        all_managed_interfaces = set(lan_network_files.keys())
        active_interfaces = set(clients_by_interface.keys())
        interfaces_to_clear = all_managed_interfaces - active_interfaces

        for lan_if in interfaces_to_clear:
            network_file = lan_network_files.get(lan_if)
            if not network_file: continue
            dropin_dir = NETWORKD_DIR / f"{network_file}.d"
            if dropin_dir.exists():
                for f in dropin_dir.glob("10-vpn-router-*.conf"):
                    logger.info(f"Removing orphaned routing rule file: {f.name}")
                    if not self.dry_run:
                        f.unlink()
                    self.changed_files.add("networkd_config")
                # Try to remove the directory if it is empty
                if not any(dropin_dir.iterdir()):
                    logger.info(f"Removing empty drop-in directory: {dropin_dir}")
                    if not self.dry_run:
                        dropin_dir.rmdir()

        # If there are no clients at all, ensure all our drop-in files are gone
        if not resolved_clients_map:
            for f in NETWORKD_DIR.glob("*.network.d/10-vpn-router-*.conf"):
                logger.info(f"No active clients. Removing orphaned routing rule file: {f.name}")
                if not self.dry_run:
                    f.unlink()
                self.changed_files.add("networkd_config")

    def _sync_firewalld_zones(self, active_vpns, orphaned_vpns):
        logger.info("Synchronizing firewalld zones...")
        firewalld_config = self.vpn_definitions['system_config'].get('firewalld', {})
        vpn_zone = firewalld_config.get('zone_vpn')

        if not vpn_zone:
            logger.warning("firewalld 'zone_vpn' is not defined in system_config. Skipping zone management.")
            return

        # Add active veth interfaces to the VPN zone
        for vpn_name in active_vpns:
            veth_if = f"v-{vpn_name}-v"
            result = self._run_cmd(['firewall-cmd', '--zone', vpn_zone, '--query-interface', veth_if], check=False)
            if result and result.returncode != 0:
                logger.info(f"Adding interface {veth_if} to firewalld zone {vpn_zone}")
                self._run_cmd(['firewall-cmd', '--zone', vpn_zone, '--add-interface', veth_if, '--permanent'])
                self.changed_files.add("firewalld_config")

        # Remove orphaned veth interfaces from the VPN zone
        for vpn_name in orphaned_vpns:
            veth_if = f"v-{vpn_name}-v"
            result = self._run_cmd(['firewall-cmd', '--zone', vpn_zone, '--query-interface', veth_if], check=False)
            if result and result.returncode == 0:
                logger.info(f"Removing interface {veth_if} from firewalld zone {vpn_zone}")
                self._run_cmd(['firewall-cmd', '--zone', vpn_zone, '--remove-interface', veth_if, '--permanent'])
                self.changed_files.add("firewalld_config")

        if "firewalld_config" in self.changed_files:
            self._run_cmd(['firewall-cmd', '--reload'])

    def _cleanup_vpn_resources(self, vpn_name):
        logger.info(f"Cleaning up resources for orphaned VPN '{vpn_name}'...")
        self._run_cmd(["systemctl", "disable", "--now", f"vpn-ns-{vpn_name}.service"], check=False)

        for f in self._get_vpn_resource_files(vpn_name):
            if f.exists():
                logger.info(f"Removing file {f}")
                if not self.dry_run: f.unlink()
        self.changed_files.add("deleted_vpn_files")

    def _check_and_cleanup_orphans(self, orphaned_vpns):
        logger.info("Checking for orphaned VPN resources...")
        
        for vpn_name in orphaned_vpns:
            logger.info(f"Processing orphaned VPN '{vpn_name}'...")
            files = self._get_vpn_resource_files(vpn_name)
            modified_files = {f for f in files if self._is_file_manually_modified(f)}

            if modified_files:
                logger.warning(f"Orphaned VPN '{vpn_name}' has manually modified files and will not be cleaned up.")
                for f in files:
                    if f.exists():
                        status = "modified" if f in modified_files else "unchanged"
                        logger.warning(f"  - {f}: {status}")
                continue

            self._cleanup_vpn_resources(vpn_name)

    def _sync_routing_tables(self, active_vpns):
        logger.info("Synchronizing routing tables...")
        RT_TABLES_DIR.mkdir(parents=True, exist_ok=True)

        desired_files = set()
        for vpn_name in active_vpns:
            vpn_config = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
            if not vpn_config or 'routing_table_id' not in vpn_config or 'routing_table_name' not in vpn_config:
                logger.warning(f"VPN '{vpn_name}' is missing routing table info. Skipping table creation.")
                continue

            table_id = vpn_config['routing_table_id']
            table_name = vpn_config['routing_table_name']
            filename = f"99-vpn-router-{vpn_name}.conf"
            desired_files.add(filename)
            content = f"{table_id} {table_name}\n"
            # Use _write_file to create the file idempotently.
            self._write_file(RT_TABLES_DIR / filename, content, mode=0o644, owner='root', group='root')

        # Cleanup orphaned files
        current_files = {f.name for f in RT_TABLES_DIR.glob("99-vpn-router-*.conf")}
        orphaned_files = current_files - desired_files

        for filename in orphaned_files:
            logger.info(f"Removing orphaned routing table file: {filename}")
            if not self.dry_run:
                (RT_TABLES_DIR / filename).unlink()
            # Use a generic key since this might trigger a reload
            self.changed_files.add("routing_tables_config")

    def run(self):
        logger.info("Starting VPN Policy Router apply run...")
        self.changed_files.clear()
        self._prune_expired_clients()
        resolved_clients_map = self._resolve_assignments()
        active_vpns = set(resolved_clients_map.keys())
        self._manage_timer(enable=bool(self.vpn_clients.get("assignments")))

        # Discover all VPNs that have any system files
        system_vpn_names = set()

        search_patterns = {
            SYSTEMD_DIR: ["vpn-ns-*.service"],
            NETWORKD_DIR: ["10-v-*-v.netdev", "10-v-*-v.network", "20-v-*-w.netdev", "30-v-*-w.network", "30-v-*-p.network"],
            RT_TABLES_DIR: ["99-vpn-router-*.conf"]
        }

        for directory, patterns in search_patterns.items():
            for pattern in patterns:
                for f in directory.glob(pattern):
                    # Extract vpn_name from filename
                    match = re.search(r'ns-([a-zA-Z0-9_-]+)\.service', f.name) or \
                            re.search(r'v-([a-zA-Z0-9_-]+)-[vpw]\.', f.name) or \
                            re.search(r'99-vpn-router-([a-zA-Z0-9_-]+)\.conf', f.name)
                    if match:
                        system_vpn_names.add(match.groups()[-1])

        orphaned_vpns = system_vpn_names - active_vpns
        self._check_and_cleanup_orphans(orphaned_vpns)

        self._sync_routing_tables(active_vpns)

        for vpn_name in active_vpns:
            vpn_config = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
            if vpn_config:
                self._apply_vpn_config(vpn_config)

        self._sync_routing_rules(resolved_clients_map)
        self._sync_firewalld_zones(active_vpns, orphaned_vpns)

        if self.changed_files and not self.dry_run:
            logger.info("Configuration changed, reloading services...")
            self._run_cmd(["systemctl", "daemon-reload"])
            self._run_cmd(["networkctl", "reload"])
            self._run_cmd(["ip", "route", "flush", "cache"])

        logger.info("Run completed.")

def main():
    parser = argparse.ArgumentParser(description="VPN Policy Router Apply Script")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if os.geteuid() != 0:
        logger.error("This script must be run as root.")
        sys.exit(1)
    router = VPNRouter(dry_run=args.dry_run, auto_mode=True)
    router.run()

if __name__ == "__main__":
    main()
