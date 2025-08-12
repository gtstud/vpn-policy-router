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
RT_TABLES_DIR = Path("/etc/iproute2/rt_tables.d")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
GENERATOR_NAME = "vpn-apply.py"
GENERATOR_VERSION = "5.0"

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
                    "firewalld": {"zone_vpn": "trusted"},
                    "veth_network_range": {"prefix": "10.239"},
                    "routing_table_id_range": {"min": 7001, "max": 7200}
                },
                "vpn_connections": []
            }
        else:
            template = {"assignments": []}
        
        if not self.dry_run:
            self._write_file(path, json.dumps(template, indent=2), mode=0o600, owner='root', group='root')
        return template

    def _validate_config(self):
        logger.info("Validating configuration...")

        # --- Validate vpn-definitions.json ---
        if "system_config" not in self.vpn_definitions:
            raise ValueError("Missing 'system_config' in vpn-definitions.json")
        if "firewalld" not in self.vpn_definitions["system_config"] or "zone_vpn" not in self.vpn_definitions["system_config"]["firewalld"]:
            raise ValueError("Missing 'firewalld.zone_vpn' in system_config")

        veth_range_config = self.vpn_definitions["system_config"].get("veth_network_range", {})
        veth_prefix = veth_range_config.get("prefix")
        if not veth_prefix:
            raise ValueError("Missing 'veth_network_range.prefix' in system_config")

        routing_table_range_config = self.vpn_definitions["system_config"].get("routing_table_id_range", {})
        min_table_id = routing_table_range_config.get("min")
        max_table_id = routing_table_range_config.get("max")
        if min_table_id is None or max_table_id is None:
            raise ValueError("Missing 'routing_table_id_range.min' or 'max' in system_config")

        vpn_conns = self.vpn_definitions.get("vpn_connections", [])
        seen_names = set()
        seen_table_ids = set()
        for vpn in vpn_conns:
            if vpn['name'] in seen_names: raise ValueError(f"Duplicate VPN name found: {vpn['name']}")
            seen_names.add(vpn['name'])

            table_id = vpn['routing_table_id']
            if not (min_table_id <= table_id <= max_table_id):
                raise ValueError(f"routing_table_id {table_id} for VPN '{vpn['name']}' is outside the allowed range {min_table_id}-{max_table_id}")
            if table_id in seen_table_ids: raise ValueError(f"Duplicate routing_table_id: {table_id}")
            seen_table_ids.add(table_id)

            try:
                veth_net = ipaddress.ip_network(vpn['veth_network'])
                if not str(veth_net.network_address).startswith(veth_prefix):
                    raise ValueError(f"veth_network '{vpn['veth_network']}' is not in the required range '{veth_prefix}.*'")
                ipaddress.ip_interface(vpn['vpn_assigned_ip']) # Use ip_interface for host IPs
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation in VPN '{vpn['name']}': {e}")

            # A simple regex for WireGuard keys (44-char Base64)
            key_regex = re.compile(r'^[A-Za-z0-9+/]{43}=$')
            if 'client_public_key' not in vpn:
                raise ValueError(f"Missing 'client_public_key' in VPN '{vpn['name']}'")
            if not key_regex.match(vpn['client_private_key']) or \
               not key_regex.match(vpn['peer_public_key']) or \
               not key_regex.match(vpn['client_public_key']):
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

    def _run_cmd(self, cmd, check=True, input=None):
        logger.debug(f"Running command: {' '.join(cmd)}")
        if self.dry_run:
            logger.info(f"DRY RUN: Would run: {' '.join(cmd)}")
            # For commands that expect JSON output, return an empty list/dict representation
            if "-j" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        try:
            return subprocess.run(cmd, check=check, capture_output=True, text=True, input=input)
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}. Is it installed?")
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}\n{e.stderr}")
            return None

    def _write_file(self, path, content, mode=0o644, owner=None, group=None):
        path = Path(path)

        # Check if file needs updating
        if path.exists():
            try:
                if path.read_text() == content and path.stat().st_mode & 0o777 == mode:
                    return
            except IOError:
                pass

        logger.info(f"Writing configuration to {path}")
        self.changed_files.add(str(path))

        if not self.dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
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
            self._write_file(VPN_CLIENTS_PATH, json.dumps(self.vpn_clients, indent=2), mode=0o600, owner='root', group='root')

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
                # Also resolve the LAN interface for this client
                lan_if = self._get_lan_interface_for_ip(ip_address)
                if not lan_if:
                    logger.warning(f"Could not determine LAN interface for IP {ip_address}. Skipping client '{client['display_name']}'.")
                    continue
                resolved_map.setdefault(vpn_name, []).append({'ip': ip_address, 'lan_if': lan_if})
        return resolved_map

    def _netns_exists(self, ns_name):
        result = self._run_cmd(['ip', 'netns', 'list'], check=False)
        return result and result.returncode == 0 and ns_name in result.stdout

    def _link_exists(self, link_name, ns_name=None):
        if ns_name:
            cmd = ['ip', '-n', ns_name, 'link', 'show', link_name]
        else:
            cmd = ['ip', 'link', 'show', link_name]
        result = self._run_cmd(cmd, check=False)
        return result and result.returncode == 0

    def _get_link_ip(self, link_name, ns_name=None):
        if ns_name:
            cmd = ['ip', '-n', ns_name, '-j', 'addr', 'show', link_name]
        else:
            cmd = ['ip', '-j', 'addr', 'show', link_name]
        result = self._run_cmd(cmd, check=False)
        if not result or result.returncode != 0:
            return None
        try:
            addr_info = json.loads(result.stdout)
            if addr_info and addr_info[0]['addr_info']:
                for addr in addr_info[0]['addr_info']:
                    if addr['family'] == 'inet':
                        return f"{addr['local']}/{addr['prefixlen']}"
        except (json.JSONDecodeError, IndexError, KeyError):
            return None
        return None

    def _get_policy_rules(self):
        result = self._run_cmd(['ip', 'rule', 'list'], check=False)
        rules = set()
        if not result or result.returncode != 0:
            return rules
        # Example output: 32765:	from 192.168.1.10 lookup vpnX_tbl
        for line in result.stdout.strip().split('\n'):
            match = re.search(r'from\s+([0-9\.]+)\s+lookup\s+([a-zA-Z0-9_-]+)', line)
            if match:
                rules.add((match.group(1), match.group(2)))
        return rules

    def _get_lan_interface_for_ip(self, ip_address):
        """Find which LAN interface an IP address belongs to."""
        try:
            # Get the route to the IP, which tells us the interface
            cmd = ['ip', '-j', 'route', 'get', ip_address]
            result = self._run_cmd(cmd, check=False)
            if not result or result.returncode != 0:
                return None
            route_info = json.loads(result.stdout)
            # For a local IP, the route info is a list containing one dict
            if route_info and isinstance(route_info, list) and 'dev' in route_info[0]:
                return route_info[0]['dev']
        except (json.JSONDecodeError, IndexError):
            pass
        logger.warning(f"Could not find route/interface for local IP: {ip_address}")
        return None

    def _get_subnet_for_interface(self, lan_if):
        """Get the IPv4 subnet for a given interface."""
        cmd = ['ip', '-j', 'addr', 'show', 'dev', lan_if]
        result = self._run_cmd(cmd, check=False)
        if not result or result.returncode != 0:
            return None
        try:
            addr_info = json.loads(result.stdout)
            if addr_info and addr_info[0].get('addr_info'):
                for addr in addr_info[0]['addr_info']:
                    if addr.get('family') == 'inet':
                        # Use the ipaddress module to correctly calculate the network address
                        ip_if = ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")
                        return str(ip_if.network)
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        logger.warning(f"Could not determine subnet for interface {lan_if}")
        return None

    def _get_table_default_route(self, table_name):
        """Check for a default route in a specific routing table."""
        cmd = ['ip', '-j', 'route', 'show', 'table', table_name]
        result = self._run_cmd(cmd, check=False)
        if not result or result.returncode != 0:
            return None
        try:
            route_info = json.loads(result.stdout)
            for route in route_info:
                if route.get("dst") == "default":
                    return {"gateway": route.get("gateway"), "dev": route.get("dev")}
        except (json.JSONDecodeError, IndexError):
            return None
        return None

    def _get_namespace_lan_routes(self, ns_name, via_ip):
        """Get LAN-specific routes from a namespace that go via a specific gateway."""
        routes = set()
        cmd = ['ip', '-j', '-n', ns_name, 'route', 'show']
        result = self._run_cmd(cmd, check=False)
        if not result or result.returncode != 0:
            return routes
        try:
            route_info = json.loads(result.stdout)
            for route in route_info:
                if route.get("gateway") == via_ip:
                    # We only want to manage private IP space routes
                    try:
                        if ipaddress.ip_network(route.get("dst")).is_private:
                            routes.add(route.get("dst"))
                    except (ValueError, TypeError):
                        continue
        except (json.JSONDecodeError, IndexError):
            pass
        return routes

    def _apply_vpn_config(self, vpn, lan_subnets):
        vpn_name = vpn["name"]
        ns_name = f"ns-{vpn_name}"
        host_veth, ns_veth = f"v-{vpn_name}-v", f"v-{vpn_name}-p"
        wg_if = f"v-{vpn_name}-w"
        host_ip, ns_ip = self._get_network_addresses(vpn["veth_network"])
        host_ip_full, ns_ip_full = f"{host_ip}/30", f"{ns_ip}/30"
        table_name = vpn["routing_table_name"]

        logger.info(f"Applying network configuration for VPN '{vpn_name}'...")

        # 1. Create Namespace if not exists
        if not self._netns_exists(ns_name):
            logger.info(f"Creating namespace {ns_name}")
            self._run_cmd(["ip", "netns", "add", ns_name])
            self.changed_files.add(f"netns_{ns_name}")

        # 2. Create veth pair if not exists
        if not self._link_exists(host_veth):
            logger.info(f"Creating veth pair {host_veth} <-> {ns_veth}")
            self._run_cmd(["ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth])
            self.changed_files.add(f"link_{host_veth}")
            # Move peer to namespace right away
            logger.info(f"Moving {ns_veth} to namespace {ns_name}")
            self._run_cmd(["ip", "link", "set", ns_veth, "netns", ns_name])

        # 3. Configure host veth
        if self._get_link_ip(host_veth) != host_ip_full:
            logger.info(f"Assigning IP {host_ip_full} to {host_veth}")
            self._run_cmd(["ip", "addr", "add", host_ip_full, "dev", host_veth])
            self.changed_files.add(f"ip_{host_veth}")
        self._run_cmd(["ip", "link", "set", host_veth, "up"])

        # 4. Configure namespace veth and lo
        self._run_cmd(["ip", "-n", ns_name, "link", "set", "lo", "up"])
        if self._get_link_ip(ns_veth, ns_name) != ns_ip_full:
            logger.info(f"Assigning IP {ns_ip_full} to {ns_veth} in {ns_name}")
            self._run_cmd(["ip", "-n", ns_name, "addr", "add", ns_ip_full, "dev", ns_veth])
            self.changed_files.add(f"ip_{ns_veth}")
        self._run_cmd(["ip", "-n", ns_name, "link", "set", ns_veth, "up"])

        # 5. Create and move WireGuard interface if not exists
        if not self._link_exists(wg_if, ns_name):
            logger.info(f"Creating WireGuard interface {wg_if}")
            self._run_cmd(["ip", "link", "add", wg_if, "type", "wireguard"])
            logger.info(f"Moving {wg_if} to namespace {ns_name}")
            self._run_cmd(["ip", "link", "set", wg_if, "netns", ns_name])
            self.changed_files.add(f"link_{wg_if}")

        # 6. Configure WireGuard interface
        # Resolve endpoint hostname if necessary
        peer_endpoint = vpn['peer_endpoint']
        try:
            host, port = peer_endpoint.rsplit(':', 1)
            ipaddress.ip_address(host)
            resolved_endpoint = peer_endpoint
        except ValueError:
            try:
                resolved_ip = socket.gethostbyname(host)
                logger.debug(f"Resolved endpoint '{host}' to '{resolved_ip}'")
                resolved_endpoint = f"{resolved_ip}:{port}"
            except socket.gaierror:
                logger.error(f"Could not resolve WireGuard endpoint hostname '{host}' for VPN '{vpn_name}'.")
                resolved_endpoint = None

        if resolved_endpoint:
            logger.info(f"Configuring WireGuard peer for {wg_if}")
            self._run_cmd([
                "ip", "netns", "exec", ns_name, "wg", "set", wg_if,
                "private-key", "/dev/stdin",
                "peer", vpn['peer_public_key'],
                "endpoint", resolved_endpoint,
                "allowed-ips", "0.0.0.0/0"
            ], input=vpn['client_private_key'])

        # 7. Assign IP to WireGuard interface
        if self._get_link_ip(wg_if, ns_name) != vpn['vpn_assigned_ip']:
            logger.info(f"Assigning IP {vpn['vpn_assigned_ip']} to {wg_if} in {ns_name}")
            self._run_cmd(["ip", "-n", ns_name, "addr", "add", vpn['vpn_assigned_ip'], "dev", wg_if])
            self.changed_files.add(f"ip_{wg_if}")

        # 8. Bring up WireGuard interface and set default route
        self._run_cmd(["ip", "-n", ns_name, "link", "set", wg_if, "up"])
        self._run_cmd(["ip", "-n", ns_name, "route", "replace", "default", "dev", wg_if])

        # 8b. Synchronize routes back to the specific LAN subnets of the clients using this VPN
        logger.info(f"Synchronizing LAN routes in {ns_name}")
        current_lan_routes = self._get_namespace_lan_routes(ns_name, host_ip)
        desired_lan_routes = lan_subnets # This is already a set

        # Add missing routes
        for subnet in (desired_lan_routes - current_lan_routes):
            logger.info(f"Adding LAN route in {ns_name} for {subnet} via {host_ip}")
            self._run_cmd(["ip", "-n", ns_name, "route", "add", subnet, "via", host_ip])
            self.changed_files.add(f"lan_route_{ns_name}_{subnet}")

        # Remove orphaned routes
        for subnet in (current_lan_routes - desired_lan_routes):
            logger.info(f"Removing stale LAN route in {ns_name} for {subnet}")
            self._run_cmd(["ip", "-n", ns_name, "route", "del", subnet])
            self.changed_files.add(f"lan_route_del_{ns_name}_{subnet}")

        # 9. Setup NAT inside the namespace
        logger.info(f"Setting up NAT inside namespace {ns_name}")
        self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'table', 'ip', 'nat'], check=False)
        self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'chain', 'ip', 'nat', 'POSTROUTING', '{ type nat hook postrouting priority 100 ; }'], check=False)
        self._run_cmd(['ip', 'netns', 'exec', ns_name, 'nft', 'add', 'rule', 'ip', 'nat', 'POSTROUTING', 'oifname', wg_if, 'masquerade'], check=False)

        # 10. Add route to custom table to direct traffic into the namespace
        logger.info(f"Synchronizing route for table '{table_name}'")
        current_route = self._get_table_default_route(table_name)
        desired_route = {"gateway": ns_ip, "dev": host_veth}
        if current_route != desired_route:
            logger.info(f"Adding default route to table '{table_name}' via {ns_ip} dev {host_veth}")
            self._run_cmd(['ip', 'route', 'replace', 'default', 'via', ns_ip, 'dev', host_veth, 'table', table_name])
            self.changed_files.add(f"route_table_{table_name}")


    def _sync_routing_rules(self, resolved_clients_map):
        logger.info("Synchronizing routing rules...")

        # 1. Get current state from the system
        current_rules = self._get_policy_rules()

        # 2. Determine desired state from config
        desired_rules = set()
        active_vpn_names = set(resolved_clients_map.keys())

        for vpn_name in active_vpn_names:
            vpn_config = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
            if not vpn_config:
                continue

            table_name = vpn_config.get("routing_table_name")
            if not table_name:
                logger.warning(f"VPN '{vpn_name}' is missing 'routing_table_name'. Cannot create routing rules.")
                continue

            for client in resolved_clients_map.get(vpn_name, []):
                desired_rules.add((client['ip'], table_name))

        # 3. Synchronize: add missing rules
        for ip, table in (desired_rules - current_rules):
            logger.info(f"Adding routing rule for {ip} to use table {table}")
            self._run_cmd(['ip', 'rule', 'add', 'from', ip, 'lookup', table])
            self.changed_files.add(f"rule_{ip}")

        # 4. Synchronize: remove orphaned rules
        # We only want to remove rules that we would have managed.
        # This is any rule pointing to a table name defined in our vpn_definitions.
        managed_table_names = {vpn.get("routing_table_name") for vpn in self.vpn_definitions['vpn_connections']}

        for ip, table in (current_rules - desired_rules):
            if table in managed_table_names:
                logger.info(f"Removing orphaned routing rule for {ip}")
                self._run_cmd(['ip', 'rule', 'del', 'from', ip, 'lookup', table])
                self.changed_files.add(f"rule_del_{ip}")


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
        ns_name = f"ns-{vpn_name}"
        host_veth = f"v-{vpn_name}-v"

        # Delete the namespace, which also removes the wg and veth-peer links
        if self._netns_exists(ns_name):
            logger.info(f"Deleting network namespace {ns_name}")
            self._run_cmd(["ip", "netns", "del", ns_name])
            self.changed_files.add(f"del_netns_{ns_name}")

        # The host-side veth link might linger
        if self._link_exists(host_veth):
            logger.info(f"Deleting host veth link {host_veth}")
            self._run_cmd(["ip", "link", "del", host_veth])
            self.changed_files.add(f"del_link_{host_veth}")

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
            self._write_file(RT_TABLES_DIR / filename, content, mode=0o644, owner='root', group='root')

        current_files = {f.name for f in RT_TABLES_DIR.glob("99-vpn-router-*.conf")}
        orphaned_files = current_files - desired_files

        for filename in orphaned_files:
            logger.info(f"Removing orphaned routing table file: {filename}")
            if not self.dry_run:
                (RT_TABLES_DIR / filename).unlink()
            self.changed_files.add("routing_tables_config")

    def _is_ip_on_interface(self, ns_name, dev, ip_with_prefix):
        """Check if a specific IP address with prefix is on an interface in a namespace."""
        current_ip = self._get_link_ip(dev, ns_name)
        if not current_ip or not ip_with_prefix:
            return False

        try:
            # Normalize and compare
            return ipaddress.ip_interface(current_ip) == ipaddress.ip_interface(ip_with_prefix)
        except ValueError:
            return False

    def _check_and_cleanup_orphans(self, active_vpns):
        logger.info("Checking for orphaned VPN resources...")
        
        # Discover existing resources by naming convention
        system_vpn_names = set()

        # Namespaces
        result = self._run_cmd(['ip', 'netns', 'list'], check=False)
        if result and result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                match = re.search(r'^ns-([a-zA-Z0-9_-]+)', line)
                if match:
                    system_vpn_names.add(match.group(1))

        # Veth links
        result = self._run_cmd(['ip', '-br', 'link', 'show', 'type', 'veth'], check=False)
        if result and result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                match = re.search(r'^v-([a-zA-Z0-9_-]+)-v', line)
                if match:
                    system_vpn_names.add(match.group(1))

        orphaned_vpns = system_vpn_names - active_vpns
        if orphaned_vpns:
            logger.info(f"Found orphaned VPNs to cleanup: {', '.join(orphaned_vpns)}")
            for vpn_name in orphaned_vpns:
                self._cleanup_vpn_resources(vpn_name)
        else:
            logger.info("No orphaned VPN resources found.")

        return orphaned_vpns


    def run(self):
        logger.info("Starting VPN Policy Router apply run...")
        self.changed_files.clear()

        self._prune_expired_clients()
        resolved_clients_map = self._resolve_assignments()
        active_vpns = set(resolved_clients_map.keys())

        # Determine required LAN subnets for each VPN
        vpn_lan_subnets = {}
        for vpn_name, clients in resolved_clients_map.items():
            subnets = set()
            for client in clients:
                subnet = self._get_subnet_for_interface(client['lan_if'])
                if subnet:
                    subnets.add(subnet)
            vpn_lan_subnets[vpn_name] = subnets

        # Cleanup phase
        orphaned_vpns = self._check_and_cleanup_orphans(active_vpns)

        # Sync phase
        self._sync_routing_tables(active_vpns)

        for vpn_name in active_vpns:
            vpn_config = next((v for v in self.vpn_definitions['vpn_connections'] if v['name'] == vpn_name), None)
            if vpn_config:
                self._apply_vpn_config(vpn_config, vpn_lan_subnets.get(vpn_name, set()))

        self._sync_routing_rules(resolved_clients_map)
        self._sync_firewalld_zones(active_vpns, orphaned_vpns)

        if self.changed_files and not self.dry_run:
            logger.info("Configuration changed, flushing route cache...")
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
