"""
Network connection monitoring and analysis
"""

import psutil
from .config import hostname_cache, is_trusted


def list_connections_fast(only_active=False):
    """Get connections quickly without hostname resolution"""
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        pid = conn.pid
        if pid is None:
            continue

        try:
            process = psutil.Process(pid)
            name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "N/A"

        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            remote_host = hostname_cache.get(remote_ip, remote_ip)
            raddr = f"{remote_host} ({remote_ip}):{remote_port}"
            connection_type = "Outbound"
        else:
            remote_ip = None
            remote_host = None
            raddr = "N/A"
            connection_type = "Listening"

        if only_active:
            if not conn.raddr or conn.status != psutil.CONN_ESTABLISHED:
                continue

        connections.append(
            {
                "name": name,
                "pid": pid,
                "laddr": laddr,
                "raddr": raddr,
                "remote_ip": remote_ip,
                "remote_host": remote_host,
                "needs_resolution": remote_ip and remote_host == remote_ip,
                "status": conn.status,
                "type": connection_type,
                "id": f"{name}_{pid}_{laddr}_{raddr}_{conn.status}",
            }
        )

    return connections


def format_connections(connections):
    """Format connections for display"""
    trusted_lines = []
    untrusted_lines = []
    listening_lines = []

    for conn in connections:
        line = f"{conn['name']:<25} PID: {conn['pid']:<6} Local: {conn['laddr']:<21} Remote: {conn['raddr']}"

        if conn["type"] == "Listening":
            listening_lines.append(line)
        elif (
            conn["remote_ip"]
            and conn["remote_host"]
            and is_trusted(conn["remote_ip"], conn["remote_host"])
        ):
            trusted_lines.append(line)
        elif conn["remote_ip"]:
            untrusted_lines.append(line)

    output = []
    if untrusted_lines:
        output.append("=== Untrusted Outbound Connections ===")
        output.extend(untrusted_lines)
        output.append("")
    if trusted_lines:
        output.append("=== Trusted Outbound Connections ===")
        output.extend(trusted_lines)
        output.append("")
    if listening_lines:
        output.append("=== Listening Connections ===")
        output.extend(listening_lines)

    return "\n".join(output) if output else "No connections found."
