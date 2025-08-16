"""
Configuration and constants
"""

from ipaddress import ip_network

# Global configuration
SHOW_ONLY_ACTIVE = True

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


def toggle_show_active():
    """Toggle the SHOW_ONLY_ACTIVE setting"""
    global SHOW_ONLY_ACTIVE
    # print(not SHOW_ONLY_ACTIVE)
    SHOW_ONLY_ACTIVE = not SHOW_ONLY_ACTIVE


def is_trusted(ip, hostname):
    """Check if ip or domain is trusted"""
    from ipaddress import ip_address

    try:
        if any(ip_address(ip) in net for net in trusted_networks):
            return True
    except ValueError:
        pass

    if any(hostname.endswith(domain) for domain in trusted_domains):
        return True
    return False
