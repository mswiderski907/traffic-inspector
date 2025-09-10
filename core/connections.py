"""
Network connection monitoring and analysis
"""

import psutil
from .config import (
    hostname_cache,
    is_trusted,
    is_connection_user_marked,
    get_connection_trust_status,
)


def analyze_process_path(process_name, exe_path):
    """Analyze if a process path looks suspicious"""
    import os
    import platform

    if exe_path in ["N/A", "Access Denied"]:
        return "Unknown", "Cannot access process path"

    try:
        # Normalize the path
        exe_path = os.path.normpath(exe_path.lower())
        process_name_lower = process_name.lower()

        system = platform.system().lower()

        if system == "windows":
            # Windows system process locations
            system_locations = [
                "c:\\windows\\system32",
                "c:\\windows\\syswow64",
                "c:\\windows",
                "c:\\program files",
                "c:\\program files (x86)",
            ]

            # Known system processes and their expected locations
            system_processes = {
                "svchost.exe": ["c:\\windows\\system32"],
                "explorer.exe": ["c:\\windows"],
                "winlogon.exe": ["c:\\windows\\system32"],
                "csrss.exe": ["c:\\windows\\system32"],
                "lsass.exe": ["c:\\windows\\system32"],
                "services.exe": ["c:\\windows\\system32"],
                "spoolsv.exe": ["c:\\windows\\system32"],
                "dwm.exe": ["c:\\windows\\system32"],
                "smss.exe": ["c:\\windows\\system32"],
            }

            # Check if it's a known system process in wrong location
            if process_name_lower in system_processes:
                expected_paths = system_processes[process_name_lower]
                process_dir = os.path.dirname(exe_path)

                if not any(
                    process_dir.startswith(expected.lower())
                    for expected in expected_paths
                ):
                    return (
                        "Suspicious",
                        f"System process running from unexpected location",
                    )
                else:
                    return "System Process", "Running from expected system location"

            # Check if it's in a system directory
            process_dir = os.path.dirname(exe_path)
            if any(process_dir.startswith(sys_loc) for sys_loc in system_locations):
                return "System Location", "Running from system directory"
            else:
                return "User Location", "Running from user/application directory"

        else:  # Linux/Mac
            system_locations = [
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/system",
                "/usr/lib",
                "/lib",
            ]

            process_dir = os.path.dirname(exe_path)
            if any(process_dir.startswith(sys_loc) for sys_loc in system_locations):
                return "System Location", "Running from system directory"
            else:
                return "User Location", "Running from user/application directory"

    except Exception:
        return "Unknown", "Could not analyze path"


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
            # Get the full executable path
            try:
                exe_path = process.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                exe_path = "Access Denied"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "N/A"
            exe_path = "N/A"

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

        # Analyze process path once and store the result
        path_analysis, path_note = analyze_process_path(name, exe_path)
        
        connections.append(
            {
                "name": name,
                "pid": pid,
                "exe_path": exe_path,
                "laddr": laddr,
                "raddr": raddr,
                "remote_ip": remote_ip,
                "remote_host": remote_host,
                "needs_resolution": remote_ip and remote_host == remote_ip,
                "status": conn.status,
                "type": connection_type,
                "id": f"{name}_{pid}_{laddr}_{raddr}_{conn.status}",
                "path_analysis": path_analysis,
                "path_note": path_note,
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

        # Add trust status indicators for user-marked connections
        if conn["remote_ip"] and is_connection_user_marked(conn["remote_ip"]):
            user_trust = get_connection_trust_status(conn["remote_ip"])
            if user_trust:
                line += " [USER: TRUSTED]"
            else:
                line += " [USER: UNTRUSTED]"

        # Add process trust indicators (only show if trusted)
        from .config import is_process_trusted
        if is_process_trusted(conn["name"], conn["exe_path"]):
            line += " [PROCESS: TRUSTED]"

        # Add security indicators for suspicious process paths
        if conn["path_analysis"] == "Suspicious":
            line += " [⚠️ SUSPICIOUS PATH]"
        elif conn["path_analysis"] == "System Process":
            line += " [🔒 SYSTEM]"

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
