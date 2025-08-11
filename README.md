# Declarative Policy-Based VPN Router (DPVR)

**Version:** 4.0
**Date:** 2025-08-09

## Overview

This system provides a declarative, policy-based routing solution for managing multiple WireGuard VPN connections on a Debian Linux router. It allows specific LAN devices to have their traffic directed through designated VPN tunnels while having zero impact on other clients.

## Features

- Fully declarative and idempotent configuration
- Per-client policy-based routing
- Dynamic DNS resolution for hostname-based client assignments
- Time-based expiry of client assignments
- Safe "dry run" mode for testing configuration changes
- Comprehensive validation to prevent misconfigurations
- Zero impact on clients not explicitly assigned to a VPN
- Automatic management of routing tables via `/etc/iproute2/rt_tables.d/`

## Prerequisites

- Debian-based Linux system
- systemd-networkd enabled and running
- nftables package installed
- WireGuard tools installed
- Python 3.6+
- iproute2 package (version 5.2.0+ for rt_tables.d support)

## Installation

1. Clone this repository or extract the files to a directory.
2. Run the installation script:
