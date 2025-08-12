# Declarative Policy-Based VPN Router (DPVR)

**Version:** 5.0
**Date:** 2025-08-12

## 1. Overview

This system provides a declarative, policy-based routing solution for managing multiple WireGuard VPN connections on a Debian Linux router. It allows specific LAN devices to have their traffic directed through designated VPN tunnels while having zero impact on other clients. The system is managed via imperative `ip` and `wg` commands, ensuring a clean separation from system-wide network managers like `systemd-networkd`.

## 2. Features

- Fully declarative and idempotent configuration using simple JSON files.
- Per-client policy-based routing using `ip rule`.
- Dynamic DNS resolution for hostname-based client assignments.
- Time-based expiry of client assignments.
- Safe "dry run" mode for testing configuration changes.
- Comprehensive validation to prevent misconfigurations.
- Zero impact on clients not explicitly assigned to a VPN.
- Automatic management of routing tables via `/etc/iproute2/rt_tables.d/`.

## 3. Prerequisites

- A Debian-based Linux system (e.g., Debian, Ubuntu).
- Root or `sudo` privileges.
- The following packages installed: `iproute2`, `wireguard-tools`, `nftables`, `firewalld`.
- Python 3.6 or newer.

## 4. Installation

1.  Clone this repository or download and extract the files to a directory on your router.
    ```bash
    git clone <repository_url>
    cd vpn-policy-router
    ```
2.  Run the installation script with `sudo`. The script will copy files to system directories and set up the `systemd` timer.
    ```bash
    sudo ./install-vpn-router.sh
    ```
3.  Configure your VPNs by editing `/etc/vpn-router/vpn-definitions.json`.
4.  Start assigning clients to VPNs using the `vpn-assign.py` tool.

## 5. Usage

The `vpn-assign.py` script is used to manage which clients are routed through a VPN. It provides a simple command-based interface.

**Note:** The script must be run with `sudo`. When run with no arguments, it will display help and the current assignments.

```bash
sudo /usr/local/bin/vpn-assign.py
```

### Listing Assignments

To see the available VPNs and a list of all currently assigned clients:

```bash
sudo /usr/local/bin/vpn-assign.py list
```

### Adding or Updating a Client Assignment

To assign a client to a VPN, or to update its assignment, use the `add` command. The client is uniquely identified by its `display-name`. If you run `add` with an existing display name, the entry will be updated.

**Required arguments:**
*   `--display-name`: A unique, friendly name for the client (e.g., "Living-Room-TV").
*   `--vpn`: The name of the VPN to use (from `vpn-definitions.json`).
*   `--ip` or `--hostname`: The client's IP address or hostname.

**Optional arguments:**
*   `--duration`: How long the assignment should last (e.g., `30m`, `2h`, `7d`). If omitted, the assignment is permanent.

**Example:** Assign an Apple TV with a static IP to `vpn1` permanently.
```bash
sudo /usr/local/bin/vpn-assign.py add \
  --display-name "Apple-TV" \
  --ip "192.168.1.50" \
  --vpn "vpn1"
```

**Example:** Assign a work laptop by its hostname to `vpn2` for 8 hours.
```bash
sudo /usr/local/bin/vpn-assign.py add \
  --display-name "Work-Laptop" \
  --hostname "laptop.lan" \
  --vpn "vpn2" \
  --duration "8h"
```

### Removing a Client Assignment

To remove a single assignment, use the `remove` command and specify the client's display name.

```bash
sudo /usr/local/bin/vpn-assign.py remove --display-name "Work-Laptop"
```

### Removing All Assignments

To remove all client assignments at once, use the `remove-all` command. For safety, you will be prompted for confirmation.

```bash
sudo /usr/local/bin/vpn-assign.py remove-all
```

Changes made with `vpn-assign.py` are applied immediately by automatically triggering the `vpn-apply.py` script.

## 6. Uninstallation

To completely remove the VPN router system from your machine, run the provided uninstallation script.

1.  Navigate to the directory where you originally cloned or extracted the files.
2.  Run the uninstall script with `sudo`.
    ```bash
    sudo ./uninstall-vpn-router.sh
    ```
The script will stop the service, remove all installed scripts and `systemd` units, and will prompt you if you also wish to delete the configuration directory (`/etc/vpn-router`).

## 7. How It Works

For a detailed technical breakdown of the components, data models, and script logic, please refer to the `vpn-policy-router-spec.md` document.
