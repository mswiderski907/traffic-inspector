"""
Configuration and constants
"""

from ipaddress import ip_network
import os
import json

# Global configuration
SHOW_ONLY_ACTIVE = True
TRUSTED_CONNECTIONS_FILE = "trusted_connections.json"
TRUSTED_PROCESSES_FILE = "trusted_processes.json"
SETTINGS_FILE = "settings.json"

# Notification settings
NOTIFICATION_SETTINGS = {
    "mode": "none",  # "none", "high_risk", "untrusted_processes"
    "enabled": True
}

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

# Format: {"process_key": {"trusted": bool, "name": str, "exe_path": str, "added_by_user": bool}}
# process_key is generated from name and exe_path for uniqueness
dynamic_trusted_processes = {}


def load_trusted_connections():
    """Load trusted connections from file"""
    global dynamic_trusted_connections
    try:
        if os.path.exists(TRUSTED_CONNECTIONS_FILE):
            with open(TRUSTED_CONNECTIONS_FILE, "r") as f:
                dynamic_trusted_connections = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError):
        dynamic_trusted_connections = {}


def load_trusted_processes():
    """Load trusted processes from file"""
    global dynamic_trusted_processes
    try:
        if os.path.exists(TRUSTED_PROCESSES_FILE):
            with open(TRUSTED_PROCESSES_FILE, "r") as f:
                dynamic_trusted_processes = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError):
        dynamic_trusted_processes = {}


def load_settings():
    """Load application settings from file"""
    global NOTIFICATION_SETTINGS
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                loaded_settings = json.load(f)
                NOTIFICATION_SETTINGS.update(loaded_settings)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError):
        pass


def save_trusted_connections():
    """Save trusted connections to file"""
    try:
        with open(TRUSTED_CONNECTIONS_FILE, "w") as f:
            json.dump(dynamic_trusted_connections, f, indent=2)
    except (PermissionError, OSError):
        pass


def save_trusted_processes():
    """Save trusted processes to file"""
    try:
        with open(TRUSTED_PROCESSES_FILE, "w") as f:
            json.dump(dynamic_trusted_processes, f, indent=2)
    except (PermissionError, OSError):
        pass


def save_settings():
    """Save application settings to file"""
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(NOTIFICATION_SETTINGS, f, indent=2)
    except (PermissionError, OSError):
        pass


def update_notification_settings(mode, enabled=True):
    """Update notification settings"""
    global NOTIFICATION_SETTINGS
    NOTIFICATION_SETTINGS["mode"] = mode
    NOTIFICATION_SETTINGS["enabled"] = enabled
    save_settings()


def generate_process_key(name, exe_path):
    """Generate a unique key for a process based on name and exe_path"""
    import hashlib
    # Use both name and normalized path for uniqueness
    key_data = f"{name.lower()}|{exe_path.lower()}"
    return hashlib.md5(key_data.encode()).hexdigest()


def mark_connection_trusted(ip, hostname, trusted=True):
    """Mark a connection as trusted or untrusted"""
    dynamic_trusted_connections[ip] = {
        "trusted": trusted,
        "hostname": hostname,
        "added_by_user": True,
    }
    save_trusted_connections()


def mark_process_trusted(name, exe_path):
    """Mark a process as trusted"""
    process_key = generate_process_key(name, exe_path)
    dynamic_trusted_processes[process_key] = {
        "trusted": True,
        "name": name,
        "exe_path": exe_path,
        "added_by_user": True,
    }
    save_trusted_processes()


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


def is_process_user_marked(name, exe_path):
    """Check if a process was manually marked by the user"""
    process_key = generate_process_key(name, exe_path)
    return process_key in dynamic_trusted_processes and dynamic_trusted_processes[process_key].get(
        "added_by_user", False
    )


def get_process_trust_status(name, exe_path):
    """Get the trust status of a process"""
    process_key = generate_process_key(name, exe_path)
    if process_key in dynamic_trusted_processes:
        return dynamic_trusted_processes[process_key]["trusted"]
    return None


def is_process_trusted(name, exe_path):
    """Check if a process is trusted (user override takes precedence)"""
    process_key = generate_process_key(name, exe_path)
    if process_key in dynamic_trusted_processes:
        return dynamic_trusted_processes[process_key]["trusted"]
    return False  # Default to untrusted if not explicitly marked


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
load_trusted_processes()
load_settings()
