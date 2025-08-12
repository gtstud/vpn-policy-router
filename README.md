# Declarative Policy-Based VPN Router (DPVR)

**Version:** 5.0
**Date:** 2025-08-12

## Overview

This system provides a declarative, policy-based routing solution for managing multiple WireGuard VPN connections on a Debian Linux router. It allows specific LAN devices to have their traffic directed through designated VPN tunnels while having zero impact on other clients. The system is managed via imperative `ip` and `wg` commands, ensuring a clean separation from system-wide network managers like `systemd-networkd`.

## Features

- Fully declarative and idempotent configuration
- Per-client policy-based routing using `ip rule`
- Dynamic DNS resolution for hostname-based client assignments
- Time-based expiry of client assignments
- Safe "dry run" mode for testing configuration changes
- Comprehensive validation to prevent misconfigurations
- Zero impact on clients not explicitly assigned to a VPN
- Automatic management of routing tables via `/etc/iproute2/rt_tables.d/`
- All network resources (namespaces, links) managed imperatively via `ip` commands.

## Prerequisites

- Debian-based Linux system
- `nftables` package installed
- `firewalld` package installed
- WireGuard tools (`wg` command) installed
- Python 3.6+
- `iproute2` package

## Installation

1. Clone this repository or extract the files to a directory.
2. Run the installation script:
