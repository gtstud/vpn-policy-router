Of course. Here is the complete and final specification presented as a single Markdown document, ready for use.

---

# Specification: Declarative Policy-Based VPN Router (DPVR)

**Version:** 4.0
**Date:** 2025-08-08

## 1.0 Purpose and Scope

This document specifies a system for managing multiple WireGuard VPN connections on a Debian Linux router. The primary goal is to enable per-client policy-based routing, allowing specific LAN devices to have their traffic directed through designated VPN tunnels.

The architecture is fully declarative and idempotent, using `systemd-networkd` as the core engine. It is designed to have zero operational impact on clients not explicitly assigned to a VPN and includes features for configuration validation and safe "dry run" execution. The system will be managed by a suite of Python scripts that interact with a structured JSON data model and handle dynamic DNS resolution for client assignments.

This specification explicitly **excludes** port forwarding capabilities.

## 2.0 System Architecture and Components

| Component | Technology / Path | Role |
| :--- | :--- | :--- |
| **Configuration Directory** | `/etc/vpn-router/` | A dedicated directory to hold all configuration files for this system. |
| **VPN Definitions** | `/etc/vpn-router/vpn-definitions.json`| Static JSON file describing available VPN tunnel infrastructure. |
| **Client Assignments** | `/etc/vpn-router/vpn-clients.json` | Dynamic JSON file mapping LAN clients to VPNs with time-based expiry. |
| **State Enforcement Script**| `/usr/local/bin/vpn-apply.py` | Python script that enforces the state defined in the JSON files. |
| **Assignment Script** | `/usr/local/bin/vpn-assign.py` | Python CLI tool for users to manage client assignments. |
| **Networking Service** | `systemd-networkd` | Declarative management of all network interfaces and routing. |
| **Firewall Service** | `nftables` | Manages firewall rules, including NAT for VPN clients. `firewalld` is used for zone management on the host. |
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
| `client_public_key` | String | The client's corresponding public key. Stored for completeness, not used in generated configurations. |
| `peer_public_key` | String | The public key of the remote WireGuard server peer. |
| `peer_endpoint` | String | The `hostname:port` of the remote WireGuard server. |
| `vpn_assigned_ip` | String (CIDR) | The IP address assigned to the client by the VPN provider (e.g., "10.64.0.2/32"). |
| `veth_network` | String (CIDR) | A private `/30` network used for the veth pair connecting the namespace to the main router. |
| `routing_table_id` | Integer | A unique numeric ID (1-252) for the policy routing table. |
| `routing_table_name`| String | A unique string name for the policy routing table (e.g., "vpnX_tbl"). |
| `router_lan_interface`| String | The name of the router's main LAN interface (e.g., "br0") where policy rules will be applied. |
| `system_config.firewalld.zone_vpn` | String | The `firewalld` zone where the host-side `veth` interfaces of active VPNs will be placed. |
| `system_config.lan_network_files` | Object | A mapping of LAN interface names to their corresponding `systemd-networkd` `.network` filenames (e.g., `{"br0": "10-lan.network"}`). |

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

*   **Purpose:** To act as an idempotent configuration agent that makes the live system state match the desired state defined in the JSON files, including performing just-in-time DNS resolution.
*   **Execution:** Run as root by the `systemd` timer or triggered by `vpn-assign.py`.

#### 4.1.1 Command-Line Interface (CLI) Specification

The script MUST use Python's `argparse` module to support three mutually exclusive modes of operation:

1.  **Default (Apply Mode):** `vpn-apply.py`
2.  **Dry Run Mode:** `vpn-apply.py --dry-run`
3.  **Validation Mode:** `vpn-apply.py --validate`

#### 4.1.2 Logging and Traceability

The script MUST use Python's standard `logging` module to output detailed, timestamped information to `stdout`/`stderr` for capture by the systemd journal.

#### 4.1.3 Logic and Workflow

1.  **Parse Arguments:** Determine if running in `apply`, `--dry-run`, or `--validate` mode.
2.  **Validation (for all modes):** Perform the comprehensive validation checks as described in section 4.1.4. In `--validate` mode, report results and exit. In `apply` or `--dry-run` mode, exit with an error if validation fails.
3.  **Phase 0: Prune Expired Clients:** Read `vpn-clients.json` and filter out any assignments where `assignment_expiry` has passed.
4.  **Phase 1: Build Resolved Assignment List:** Create an in-memory list of active, resolved assignments by performing DNS lookups for all hostname-based assignments. Unresolvable hosts are skipped for this run.
5.  **Phase 2 & 3: Generate, Compare, and Apply:**
    *   **Orphan Cleanup:** Identify and remove all resources (systemd files, `nftables` rules, `firewalld` zone entries) associated with orphaned VPNs (i.e., those with no active clients). If any configuration files for an orphan have been manually modified, the cleanup for that orphan is skipped and a warning is logged.
    *   **Active VPNs:** For each active VPN, ensure all required `systemd-networkd` files are created and up-to-date.
    *   **Routing Rules:** Create per-client `systemd-networkd` drop-in files with `[RoutingPolicyRule]` sections to declaratively manage policy routing.
    *   **Firewall:** Idempotently add the host-side `veth` interface for each active VPN to the configured `firewalld` zone.
    *   **NAT:** Idempotently add an `nftables` masquerade rule for each active VPN.
    *   **Service Reloads:** In `apply` mode, execute `systemctl daemon-reload`, `networkctl reload`, or `firewall-cmd --reload` only if changes were detected.

#### 4.1.4 Validation Logic (`--validate` mode)

The validation process will check for:
*   JSON syntax and schema correctness.
*   Cross-file integrity (e.g., `assigned_vpn` points to a real VPN).
*   Network value sanity (e.g., `veth_network` is a `/30` CIDR).
*   Uniqueness of identifiers (`vpn.name`, `client.display_name`).
*   Mutual exclusion of `hostname` and `ip_address` fields for all clients.

### 4.2 Client Assignment Script: `vpn-assign.py`

*   **Purpose:** To provide a non-interactive, user-friendly CLI for managing the `vpn-clients.json` file.
*   **Execution:** Run manually as root from the command line.

#### 4.2.1 Command-Line Interface (CLI) Specification

The script MUST use Python's `argparse` module to provide a standard, non-interactive CLI.

*   **List Mode:** `vpn-assign.py --list`
    *   If run with `--list`, the script MUST print formatted lists of available VPNs and current client assignments, then exit. This is the default action if no other command is given.
*   **Create/Modify Mode (Named Arguments):** `vpn-assign.py --display-name <name> --vpn <vpn_name> [--ip <ip> | --hostname <host>] [--duration <duration>]`
    *   The script uses named arguments for all create/modify operations for clarity and extensibility.
    *   `--display-name`: The unique name for the client entry.
    *   `--vpn`: The VPN name to assign, or `none`.
    *   `--ip` / `--hostname`: **Mutually exclusive.** The technical identifier for a *new* client.
    *   `--duration`: Optional duration string (e.g., "30 days").

#### 4.2.2 Logic and Workflow

1.  **Parse arguments.** If `--list` is present or no other command-line arguments are provided, execute list mode and exit.
2.  **Acquire a file lock** on `vpn-clients.json` and read the data.
3.  **Find or Create Client:**
    *   Search for an existing client entry matching the `--display-name`.
    *   **If client exists:** Proceed to update it. If `--ip` or `--hostname` are provided for an existing client, exit with an error (technical identifiers should not be changed this way).
    *   **If client does not exist:**
        *   Check that either `--ip` or `--hostname` is provided. If not, exit with an error stating that a technical identifier is required for new clients.
        *   Create a new client object in the assignments list.
4.  **Update Client Data:** Update the `assigned_vpn` and calculate the `assignment_expiry` based on the provided arguments.
5.  **Write and Trigger:** Write the modified data back to `vpn-clients.json`, release the lock, and trigger `vpn-apply.py` to immediately enforce the change.

## 5.0 Automation and Persistence

*   A `systemd` service file, `/etc/systemd/system/vpn-apply.service`, will define the execution of `vpn-apply.py`.
*   A `systemd` timer file, `/etc/systemd/system/vpn-apply.timer`, will run the service periodically (e.g., every 15 minutes).
*   The timer will be enabled via `systemctl enable --now vpn-apply.timer` to ensure it starts on boot and runs immediately.
