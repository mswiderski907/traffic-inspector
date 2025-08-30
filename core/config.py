"""
Configuration and constants
"""

from ipaddress import ip_network
import os
import json

# Global configuration
SHOW_ONLY_ACTIVE = True
TRUSTED_CONNECTIONS_FILE = "trusted_connections.json"

# Network configuration
trusted_networks = [
    ip_network("127.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("10.0.0.0/8"),
    ip_network("::1"),
    ip_network("172.172.255.218"),  # svchost connection to Microsoft
]

trusted_domains = []

# Cache for resolved hostnames
hostname_cache = {}

# Format: {"ip": {"trusted": bool, "hostname": str, "added_by_user": bool}}
dynamic_trusted_connections = {}


def load_trusted_connections():
    """Load trusted connections from file"""
    global dynamic_trusted_connections
    try:
        if os.path.exists(TRUSTED_CONNECTIONS_FILE):
            with open(TRUSTED_CONNECTIONS_FILE, "r") as f:
                dynamic_trusted_connections = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError):
        dynamic_trusted_connections = {}


def save_trusted_connections():
    """Save trusted connections to file"""
    try:
        with open(TRUSTED_CONNECTIONS_FILE, "w") as f:
            json.dump(dynamic_trusted_connections, f, indent=2)
    except (PermissionError, OSError):
        pass


def mark_connection_trusted(ip, hostname, trusted=True):
    """Mark a connection as trusted or untrusted"""
    dynamic_trusted_connections[ip] = {
        "trusted": trusted,
        "hostname": hostname,
        "added_by_user": True,
    }
    save_trusted_connections()


def is_connection_user_marked(ip):
    """Check if a connection was manually marked by the user"""
    return ip in dynamic_trusted_connections and dynamic_trusted_connections[ip].get(
        "added_by_user", False
    )


def get_connection_trust_status(ip):
    """Get the trust status of a connection"""
    if ip in dynamic_trusted_connections:
        return dynamic_trusted_connections[ip]["trusted"]
    return None


def toggle_show_active():
    """Toggle the SHOW_ONLY_ACTIVE setting"""
    global SHOW_ONLY_ACTIVE
    # print(not SHOW_ONLY_ACTIVE)
    SHOW_ONLY_ACTIVE = not SHOW_ONLY_ACTIVE


def is_trusted(ip, hostname):
    """Check if ip or domain is trusted"""
    from ipaddress import ip_address

    if ip in dynamic_trusted_connections:
        return dynamic_trusted_connections[ip]["trusted"]
    try:
        if any(ip_address(ip) in net for net in trusted_networks):
            return True
    except ValueError:
        pass

    if any(hostname.endswith(domain) for domain in trusted_domains):
        return True
    return False


load_trusted_connections()
