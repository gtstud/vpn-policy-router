#!/usr/bin/env python3
"""
VPN Policy Router Assignment Tool
This script manages client assignments to VPN connections using a simple,
subcommand-based interface.
"""

import os
import sys
import re
import json
import argparse
import logging
import subprocess
import fcntl
from pathlib import Path
from datetime import datetime, timedelta, timezone

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('vpn-assign')

CONFIG_DIR = Path("/etc/vpn-router")
VPN_DEFINITIONS_PATH = CONFIG_DIR / "vpn-definitions.json"
VPN_CLIENTS_PATH = CONFIG_DIR / "vpn-clients.json"
APPLY_SCRIPT_PATH = "/usr/local/bin/vpn-apply.py"

TIME_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}

# --- Core Functions ---

def load_json(path: Path) -> dict:
    """Loads a JSON file and returns its content. Note: Does not lock."""
    if not path.exists():
        logger.warning(f"Config file not found: {path}. Assuming empty.")
        if path == VPN_CLIENTS_PATH:
            return {"assignments": []}
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load or parse {path}: {e}")
        sys.exit(1)

def apply_configuration(verbose: bool = False):
    """Triggers the vpn-apply.py script to enforce the new state."""
    if not Path(APPLY_SCRIPT_PATH).exists():
        logger.error(f"Apply script not found at {APPLY_SCRIPT_PATH}. Cannot apply changes.")
        return
    try:
        logger.info("Applying new configuration...")
        cmd = [APPLY_SCRIPT_PATH]
        if verbose:
            cmd.append("--verbose")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Configuration applied successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to apply configuration. Error:\n{e.stderr}")
    except FileNotFoundError:
        logger.error(f"Error: The script '{APPLY_SCRIPT_PATH}' was not found.")

def parse_duration(duration_str: str) -> int:
    """Parses a duration string like '30m', '2h', '1d' into seconds."""
    if not duration_str:
        raise ValueError("Duration string cannot be empty.")
    match = re.match(r'^(\d+)([smhd])$', duration_str.lower())
    if not match:
        raise ValueError(f"Invalid duration format: '{duration_str}'. Use '30m', '2h', etc.")
    value, unit = int(match.group(1)), match.group(2)
    return value * TIME_UNITS[unit]

# --- Command Handlers ---

def handle_list_assignments(args: argparse.Namespace):
    """Displays available VPNs and all current client assignments."""
    vpn_defs = load_json(VPN_DEFINITIONS_PATH).get("vpn_connections", [])
    client_data = load_json(VPN_CLIENTS_PATH).get("assignments", [])

    print("\n\033[1m=== Available VPN Connections ===\033[0m")
    if vpn_defs:
        print(f"{'Name':<15} {'Description'}")
        print("-" * 45)
        for vpn in vpn_defs:
            print(f"{vpn.get('name', 'N/A'):<15} {vpn.get('description', 'N/A')}")
    else:
        print("No VPNs defined in vpn-definitions.json")

    print("\n\033[1m=== Current Client Assignments ===\033[0m")
    if client_data:
        print(f"{'Display Name':<20} {'Identifier':<20} {'Assigned VPN':<15} {'Status'}")
        print("-" * 80)
        now = datetime.now(timezone.utc)
        for client in client_data:
            identifier = client.get("hostname") or client.get("ip_address") or "N/A"
            expiry_str = client.get("assignment_expiry")
            status = "Permanent"
            if expiry_str:
                try:
                    expiry_date = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                    if expiry_date < now:
                        status = f"\033[91mEXPIRED on {expiry_date.strftime('%Y-%m-%d')}\033[0m"
                    else:
                        time_left = expiry_date - now
                        days, rem = divmod(time_left.total_seconds(), 86400)
                        hours, rem = divmod(rem, 3600)
                        mins = rem // 60
                        if days >= 1:
                            status = f"Expires in {int(days)}d {int(hours)}h"
                        else:
                            status = f"Expires in {int(hours)}h {int(mins)}m"
                except (ValueError, TypeError):
                    status = f"\033[93mInvalid expiry format\033[0m"

            print(f"{client.get('display_name', 'N/A'):<20} {identifier:<20} {client.get('assigned_vpn', 'N/A'):<15} {status}")
    else:
        print("No client assignments found.")

def handle_add_assignment(args: argparse.Namespace):
    """Adds or updates a client assignment."""
    # Check for valid VPN name before touching files
    vpn_defs = load_json(VPN_DEFINITIONS_PATH)
    valid_vpns = {vpn["name"] for vpn in vpn_defs.get("vpn_connections", [])}
    if args.vpn not in valid_vpns:
        logger.error(f"Invalid VPN name: '{args.vpn}'. Valid options are: {', '.join(valid_vpns) or 'None'}")
        sys.exit(1)

    try:
        # Open with 'a+' to create if not exists, then move to start for reading
        with open(VPN_CLIENTS_PATH, 'a+') as f:
            f.seek(0)
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

            try:
                clients_data = json.load(f)
            except json.JSONDecodeError:
                clients_data = {"assignments": []}

            assignments = clients_data.setdefault("assignments", [])

            expiry = None
            if args.duration:
                try:
                    seconds = parse_duration(args.duration)
                    expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
                    expiry = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except ValueError as e:
                    logger.error(f"Error parsing duration: {e}")
                    sys.exit(1)

            new_assignment = {
                "display_name": args.display_name,
                "hostname": args.hostname,
                "ip_address": args.ip,
                "assigned_vpn": args.vpn,
                "assignment_expiry": expiry,
            }

            existing_index = next((i for i, c in enumerate(assignments) if c.get("display_name") == args.display_name), None)
            if existing_index is not None:
                logger.info(f"Updating existing assignment for '{args.display_name}'.")
                assignments[existing_index] = new_assignment
            else:
                logger.info(f"Creating new assignment for '{args.display_name}'.")
                assignments.append(new_assignment)

            f.seek(0)
            f.truncate()
            json.dump(clients_data, f, indent=2)

            logger.info("Assignments file updated successfully.")

    except (IOError, BlockingIOError):
        logger.error(f"Could not acquire lock on {VPN_CLIENTS_PATH}. Is another instance running?")
        sys.exit(1)

    # Apply configuration after the lock is released
    apply_configuration(args.verbose)

def handle_remove_assignment(args: argparse.Namespace):
    """Removes a client assignment by its display name."""
    removed = False
    try:
        with open(VPN_CLIENTS_PATH, 'a+') as f:
            f.seek(0)
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

            try:
                clients_data = json.load(f)
            except json.JSONDecodeError:
                clients_data = {"assignments": []}

            assignments = clients_data.get("assignments", [])
            original_count = len(assignments)

            assignments = [c for c in assignments if c.get("display_name") != args.display_name]

            if len(assignments) < original_count:
                clients_data["assignments"] = assignments
                f.seek(0)
                f.truncate()
                json.dump(clients_data, f, indent=2)
                logger.info(f"Removed assignment for '{args.display_name}'.")
                removed = True
            else:
                logger.error(f"No assignment found with display name '{args.display_name}'.")
                sys.exit(1)

    except (IOError, BlockingIOError):
        logger.error(f"Could not acquire lock on {VPN_CLIENTS_PATH}. Is another instance running?")
        sys.exit(1)

    if removed:
        apply_configuration(args.verbose)

def handle_remove_all_assignments(args: argparse.Namespace):
    """Removes all client assignments after user confirmation."""
    removed = False
    try:
        with open(VPN_CLIENTS_PATH, 'a+') as f:
            f.seek(0)
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

            try:
                clients_data = json.load(f)
                assignments = clients_data.get("assignments", [])
            except json.JSONDecodeError:
                assignments = []

            if not assignments:
                logger.info("No assignments to remove.")
                return

            print(f"\033[93mWARNING: This will permanently remove all {len(assignments)} client assignments.\033[0m")
            try:
                confirm = input("Are you sure you want to continue? [y/N] ")
                if confirm.lower() != 'y':
                    logger.info("Operation cancelled.")
                    return
            except (EOFError, KeyboardInterrupt):
                logger.info("\nOperation cancelled.")
                return

            logger.info("Removing all client assignments...")
            clients_data["assignments"] = []

            f.seek(0)
            f.truncate()
            json.dump(clients_data, f, indent=2)
            logger.info("All assignments removed successfully.")
            removed = True

    except (IOError, BlockingIOError):
        logger.error(f"Could not acquire lock on {VPN_CLIENTS_PATH}. Is another instance running?")
        sys.exit(1)

    if removed:
        apply_configuration(args.verbose)

def main():
    """Main function to parse arguments and call handlers."""
    parser = argparse.ArgumentParser(
        description="A tool to manage client-to-VPN assignments.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Run with no arguments to see current assignments."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed script output.")
    
    subparsers = parser.add_subparsers(dest='command', title='Available Commands')

    # --- List Command ---
    subparsers.add_parser('list', help='List available VPNs and current client assignments.')

    # --- Add/Update Command ---
    parser_add = subparsers.add_parser('add', help='Add or update a client assignment.')
    parser_add.add_argument("--display-name", required=True, help="A unique, friendly name for the client device.")
    parser_add.add_argument("--vpn", required=True, help="The name of the VPN to assign the client to.")
    group = parser_add.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="The static IP address of the client device.")
    group.add_argument("--hostname", help="The DNS-resolvable hostname of the client device.")
    parser_add.add_argument("--duration", help="Optional assignment duration (e.g., '30m', '2h', '1d').\nIf omitted, the assignment is permanent.")

    # --- Remove Command ---
    parser_remove = subparsers.add_parser('remove', help='Remove a client assignment.')
    parser_remove.add_argument("--display-name", required=True, help="The display name of the client assignment to remove.")

    # --- Remove All Command ---
    subparsers.add_parser('remove-all', help='Remove all client assignments after confirmation.')

    # If no command is provided, show help and then list current state
    if len(sys.argv) == 1:
        parser.print_help()
        handle_list_assignments(None)
        sys.exit(0)
    
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        logger.error("This script must be run as root.")
        sys.exit(1)

    if args.command == 'list':
        handle_list_assignments(args)
    elif args.command == 'add':
        handle_add_assignment(args)
    elif args.command == 'remove':
        handle_remove_assignment(args)
    elif args.command == 'remove-all':
        handle_remove_all_assignments(args)
    else:
        # This case should not be hit if a command is provided,
        # but as a fallback, show help.
        parser.print_help()

if __name__ == "__main__":
    main()
