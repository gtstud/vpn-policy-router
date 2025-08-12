Of course. Here is the complete and final specification presented as a single Markdown document, ready for use.

---

# Specification: Declarative Policy-Based VPN Router (DPVR)

**Version:** 5.0
**Date:** 2025-08-12

## 1.0 Purpose and Scope

This document specifies a system for managing multiple WireGuard VPN connections on a Debian Linux router. The primary goal is to enable per-client policy-based routing, allowing specific LAN devices to have their traffic directed through designated VPN tunnels.

The architecture is fully declarative and idempotent, using imperative `ip` and `wg` commands to manage network resources, ensuring zero interference with other network management tools like `systemd-networkd`. It is designed to have no operational impact on clients not explicitly assigned to a VPN and includes features for configuration validation and safe "dry run" execution. The system is managed by a suite of Python scripts that interact with a structured JSON data model.

This specification explicitly **excludes** port forwarding capabilities.

## 2.0 System Architecture and Components

| Component | Technology / Path | Role |
| :--- | :--- | :--- |
| **Configuration Directory** | `/etc/vpn-router/` | A dedicated directory to hold all configuration files for this system. |
| **VPN Definitions** | `/etc/vpn-router/vpn-definitions.json`| Static JSON file describing available VPN tunnel infrastructure. |
| **Client Assignments** | `/etc/vpn-router/vpn-clients.json` | Dynamic JSON file mapping LAN clients to VPNs with time-based expiry. |
| **State Enforcement Script**| `/usr/local/bin/vpn-apply.py` | Python script that enforces the state defined in the JSON files. |
| **Assignment Script** | `/usr/local/bin/vpn-assign.py` | Python CLI tool for users to manage client assignments. |
| **Networking Tools** | `iproute2`, `wireguard-tools` | Manages all network resources (namespaces, links, IPs, routes, rules). |
| **Firewall Service** | `nftables`, `firewalld` | Manages firewall rules, including NAT for VPN clients and zone management on the host. |
| **Automation Mechanism** | `systemd` Timer | Periodically runs `vpn-apply.py` to enforce state and prune expired assignments. |

## 3.0 Configuration Data Model

### 3.1 `vpn-definitions.json`

This file is the static source of truth for the VPN infrastructure.

> **Security:** This file contains sensitive private keys and **MUST** have file permissions set to `600` (`-rw-------`) and be owned by `root:root`.

| Field | Type | Description |
| :--- | :--- | :--- |
| `vpn_connections` | Array of Objects | A list containing all VPN connection definitions. |
| `name` | String | A unique, human-readable name for the VPN (e.g., "vpnX"). |
| `description` | String | Optional description of the VPN endpoint (e.g., "Provider X - London"). |
| `client_private_key`| String | The client's WireGuard private key. |
| `client_public_key` | String | The client's corresponding public key. Stored for record-keeping. |
| `peer_public_key` | String | The public key of the remote WireGuard server peer. |
| `peer_endpoint` | String | The `hostname:port` of the remote WireGuard server. |
| `vpn_assigned_ip` | String (CIDR) | The IP address assigned to the client by the VPN provider (e.g., "10.64.0.2/32"). |
| `veth_network` | String (CIDR) | A private `/30` network used for the veth pair connecting the namespace to the main router. |
| `routing_table_id` | Integer | A unique numeric ID for the policy routing table. **MUST** be within the `routing_table_id_range`. |
| `routing_table_name`| String | A unique string name for the policy routing table (e.g., "vpnX_tbl"). |
| `system_config.firewalld.zone_vpn` | String | The `firewalld` zone where the host-side `veth` interfaces of active VPNs will be placed. |
| `system_config.veth_network_range.prefix` | String | A string prefix (e.g., "10.239") that all `veth_network` values must start with. |
| `system_config.routing_table_id_range` | Object | An object defining the allowable range for `routing_table_id` values. |
| `routing_table_id_range.min` | Integer | The minimum allowable `routing_table_id`. |
| `routing_table_id_range.max` | Integer | The maximum allowable `routing_table_id`. |

### 3.2 `vpn-clients.json`

This file stores the dynamic client-to-VPN mappings.

> **Data Integrity Rule:** For each object in the `assignments` array, exactly one of `hostname` or `ip_address` **MUST** be a string, and the other **MUST** be `null`.

| Field | Type | Description |
| :--- | :--- | :--- |
| `display_name` | String | A mandatory, unique, human-readable name for the client device (e.g., "Living-Room-TV"). |
| `hostname` | String or Null | A DNS-resolvable hostname for the client device. **Mutually exclusive with `ip_address`.** |
| `ip_address` | String or Null | The static IP address of the client device. **Mutually exclusive with `hostname`.** |
| `assigned_vpn` | String or Null | The `name` of the VPN to use (must match a name in `vpn-definitions.json`), or `null` for default routing. |
| `assignment_expiry`| String (ISO 8601) or Null | The UTC timestamp (e.g., "2025-09-08T10:00:00Z") when the assignment expires. `null` for a permanent assignment. |

## 4.0 Core System Scripts

### 4.1 State Enforcement Script: `vpn-apply.py`

*   **Purpose:** To act as an idempotent configuration agent that makes the live system state match the desired state defined in the JSON files.
*   **Execution:** Run as root by the `systemd` timer or triggered by `vpn-assign.py`.

#### 4.1.1 Command-Line Interface (CLI) Specification

The script MUST use Python's `argparse` module to support:
*   `vpn-apply.py`: Default apply mode.
*   `vpn-apply.py --dry-run`: Shows what would change without executing.
*   `--verbose`: Enables debug logging.

#### 4.1.2 Logging and Traceability

The script MUST use Python's standard `logging` module to output detailed, timestamped information to `stdout`/`stderr` for capture by the systemd journal.

#### 4.1.3 Logic and Workflow

1.  **Prune Expired Clients:** Read `vpn-clients.json` and filter out any assignments where `assignment_expiry` has passed.
2.  **Build Resolved Assignment List:** Create an in-memory list of active, resolved assignments by performing DNS lookups for all hostname-based assignments. Unresolvable hosts are skipped.
3.  **Orphan Cleanup:** Discover all network resources (namespaces, veth links) that follow the system's naming convention. Any resource not corresponding to an active VPN is considered an orphan and is removed.
4.  **Synchronize Active VPNs:** For each active VPN, the script will idempotently:
    *   Ensure the network namespace (`ns-<vpn_name>`) exists.
    *   Ensure the `veth` pair (`v-<vpn_name>-v` <-> `v-<vpn_name>-p`) exists and is configured with the correct IPs.
    *   Ensure the WireGuard interface (`v-<vpn_name>-w`) exists inside the namespace and is configured with the private key and peer information.
    *   Set the default route inside the namespace to use the WireGuard interface.
    *   Set up an `nftables` masquerade rule for outbound traffic within the namespace.
5.  **Synchronize Routing Rules:** The script will compare the output of `ip rule list` with the desired state from the client assignments and use `ip rule add/del` to bring the system into compliance.
6.  **Synchronize Firewall:** The script will idempotently add the host-side `veth` interface for each active VPN to the configured `firewalld` zone and remove interfaces for orphaned VPNs.
7.  **Flush Caches:** If any changes were made, the IP route cache will be flushed to ensure new rules take effect immediately.

#### 4.1.4 Validation Logic
The script performs validation on startup, checking for:
*   JSON syntax and schema correctness.
*   Cross-file integrity (e.g., `assigned_vpn` points to a real VPN).
*   Network value sanity (e.g., `veth_network` is a `/30` CIDR).
*   Uniqueness of identifiers (`vpn.name`, `client.display_name`).
*   Mutual exclusion of `hostname` and `ip_address` fields for all clients.

### 4.2 Client Assignment Script: `vpn-assign.py`

*   **Purpose:** To provide a clear, subcommand-based CLI for managing the `vpn-clients.json` file.
*   **Execution:** Run manually as root from the command line.

#### 4.2.1 Command-Line Interface (CLI) Specification

The script MUST use Python's `argparse` module with subparsers to provide a standard, non-interactive CLI. When run with no arguments, it MUST display the help text followed by the output of the `list` command.

*   **List Command:** `vpn-assign.py list`
    *   **Action:** Displays all available VPN definitions and a list of all current client assignments, including their expiry status.
*   **Add/Update Command:** `vpn-assign.py add --display-name <name> --vpn <vpn_name> (--ip <ip> | --hostname <host>) [--duration <d>]`
    *   **Action:** Creates a new client assignment or updates an existing one identified by `--display-name`.
    *   `--display-name`: The mandatory, unique, human-readable name for the client.
    *   `--vpn`: The name of the VPN to assign (must exist in `vpn-definitions.json`).
    *   `--ip` or `--hostname`: A mandatory, mutually exclusive identifier for the client.
    *   `--duration`: An optional assignment duration (e.g., `30m`, `2h`, `1d`). If omitted, the assignment is permanent.
*   **Remove Command:** `vpn-assign.py remove --display-name <name>`
    *   **Action:** Removes the client assignment matching the specified `--display-name`.
*   **Remove All Command:** `vpn-assign.py remove-all`
    *   **Action:** Removes all client assignments after prompting the user for confirmation.

#### 4.2.2 Logic and Workflow

1.  **Parse Subcommand and Arguments:** The script determines which command (`list`, `add`, `remove`) was invoked.
2.  **Acquire File Lock:** To prevent race conditions, the script should acquire a lock on `vpn-clients.json` before reading or writing.
3.  **Perform Action:**
    *   For `add`, it finds an existing client by `display_name` to update, or appends a new assignment object to the list.
    *   For `remove`, it filters the list, removing the client object with the matching `display_name`.
4.  **Write and Trigger:** The script writes the modified data back to `vpn-clients.json`, releases the lock, and triggers `vpn-apply.py` to immediately enforce the change.

## 5.0 Automation and Persistence

*   A `systemd` service file, `/etc/systemd/system/vpn-router.service`, will define the execution of `vpn-apply.py`.
*   A `systemd` timer file, `/etc/systemd/system/vpn-router.timer`, will run the service periodically (e.g., every 15 minutes).
*   The timer will be enabled via `systemctl enable --now vpn-router.timer` to ensure it starts on boot and runs immediately.
