import tkinter as tk
from threading import Thread, Event
import socket
import os
import sys
from ipaddress import ip_address, ip_network
import psutil
import pystray
from PIL import Image, ImageDraw
import time

# TODO: fix 'async handler deleted by the wrong thread' crash after hitting exit button
# TODO: make the 'View' banner at the top of the window into a dropdown select, can get rid of menu option
# TODO: Add a way to permanently save trusted connections (maybe an option to mark a connection as trusted)
# TODO: notification for new untrusted connections (must be able to mute/disable)
# TODO: make the window look better
# TODO: run on windows startup
# TODO: add a taskbar icon
# TODO: option to hide loopback addresses
# TODO: make the scroll wheel not reset when window is updated
# TODO: maybe an option to show where on the PC a service is running
# TODO: auto-updating list of malicious IPs that trigger notifications?

hostname_cache = {}

trusted_networks = [
    ip_network("127.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("10.0.0.0/8"),
    ip_network("::1"),
    ip_network("172.172.255.218"),  # svchost connection to Microsoft
]

trusted_domains = []

SHOW_ONLY_ACTIVE = True

window_open = False
current_window = None
monitor_thread = None
stop_monitoring = Event()


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


def resolve_hostname_async(ip, text_widget_ref, connections_ref):
    """Resolve hostname in background and update display"""
    if ip in hostname_cache:
        return
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = hostname

        if window_open and text_widget_ref[0] is not None:
            try:
                text_widget = text_widget_ref[0]
                if text_widget and text_widget.winfo_exists():
                    text_widget.after(
                        0,
                        lambda: update_display_from_cache(
                            text_widget_ref, connections_ref
                        ),
                    )
            except (tk.TclError, RuntimeError, AttributeError):
                pass

    except socket.herror:
        hostname_cache[ip] = ip
    except (tk.TclError, RuntimeError):
        pass


def update_display_from_cache(text_widget_ref, connections_ref):
    """Update existing connections with resolved hostnames from cache"""
    if not window_open:
        return

    try:
        text_widget = text_widget_ref[0]
        if not text_widget.winfo_exists():
            return

        connections = connections_ref[0]
        status_label = connections_ref[1] if len(connections_ref) > 1 else None

        if status_label and status_label.winfo_exists():
            status_label.config(
                text=f"View: {'Active Connections Only' if SHOW_ONLY_ACTIVE else 'All Connections'}"
            )

        for conn in connections:
            if conn["remote_ip"] and conn["remote_ip"] in hostname_cache:
                resolved_host = hostname_cache[conn["remote_ip"]]
                if resolved_host != conn["remote_host"]:
                    conn["remote_host"] = resolved_host
                    conn["raddr"] = (
                        f"{resolved_host} ({conn['remote_ip']}):{conn['raddr'].split(':')[-1]}"
                    )
                    conn["needs_resolution"] = False

        text_widget.delete("1.0", tk.END)
        text_widget.insert("1.0", format_connections(connections))
    except (tk.TclError, RuntimeError, AttributeError):
        pass


def monitor_connections(text_widget_ref, connections_ref):
    """Monitor for new connections and update display"""
    last_connections = set()
    last_show_mode = SHOW_ONLY_ACTIVE

    while not stop_monitoring.is_set():
        try:
            if not window_open:
                break

            text_widget = text_widget_ref[0]
            if not text_widget:
                break

            try:
                if not text_widget.winfo_exists():
                    break
            except (tk.TclError, AttributeError):
                break

            mode_changed = last_show_mode != SHOW_ONLY_ACTIVE
            last_show_mode = SHOW_ONLY_ACTIVE

            current_connections = list_connections_fast(SHOW_ONLY_ACTIVE)
            current_ids = {conn["id"] for conn in current_connections}

            if current_ids != last_connections or mode_changed:
                connections_ref[0] = current_connections

                if window_open and text_widget and text_widget.winfo_exists():
                    try:
                        text_widget.after(
                            0,
                            lambda: update_display_from_cache(
                                text_widget_ref, connections_ref
                            ),
                        )
                    except (tk.TclError, RuntimeError, AttributeError):
                        break

                for conn in current_connections:
                    if conn["needs_resolution"]:
                        Thread(
                            target=resolve_hostname_async,
                            args=(conn["remote_ip"], text_widget_ref, connections_ref),
                            daemon=True,
                        ).start()

                last_connections = current_ids

            stop_monitoring.wait(4.0)
        except (tk.TclError, RuntimeError, AttributeError):
            break
        except Exception as e:
            print(f"Error in monitor_connections: {e}")
            stop_monitoring.wait(4.0)


def is_trusted(ip, hostname):
    """Check if ip or domain is trusted"""
    try:
        if any(ip_address(ip) in net for net in trusted_networks):
            return True
    except ValueError:
        pass

    if any(hostname.endswith(domain) for domain in trusted_domains):
        return True
    return False


def toggle_view(icon, item):
    """Toggle to view only active connections"""
    global SHOW_ONLY_ACTIVE
    SHOW_ONLY_ACTIVE = not SHOW_ONLY_ACTIVE
    icon.menu = create_menu()

    if window_open and current_window:
        try:
            if current_window.winfo_exists():
                stop_monitoring.set()
                stop_monitoring.clear()
        except (tk.TclError, AttributeError):
            pass


def show_window():
    """Display connections window"""
    global window_open, current_window, monitor_thread, stop_monitoring

    if window_open:
        if current_window:
            try:
                if current_window.winfo_exists():
                    current_window.lift()
                    current_window.focus_force()
            except (tk.TclError, AttributeError):
                pass
        return

    window_open = True
    stop_monitoring.clear()

    root = tk.Tk()
    root.title("Active Connections")
    root.geometry("1000x700")

    frame = tk.Frame(root)
    frame.pack(fill="both", expand=True, padx=5, pady=5)

    status_label = tk.Label(
        frame,
        text=f"View: {'Active Connections Only' if SHOW_ONLY_ACTIVE else 'All Connections'}",
        font=("Consolas", 9),
        bg="lightgray",
    )
    status_label.pack(fill="x", pady=(0, 5))

    text = tk.Text(frame, wrap="none", font=("consolas", 9))

    v_scrollbar = tk.Scrollbar(frame, orient="vertical", command=text.yview)
    h_scrollbar = tk.Scrollbar(frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

    v_scrollbar.pack(side="right", fill="y")
    h_scrollbar.pack(side="bottom", fill="x")
    text.pack(side="left", fill="both", expand=True)

    connections = list_connections_fast(SHOW_ONLY_ACTIVE)
    connections_ref = [connections, status_label]

    text_widget_ref = [text]

    text.insert("1.0", format_connections(connections))

    def close_window():
        global window_open, current_window, monitor_thread
        window_open = False
        stop_monitoring.set()

        text_widget_ref[0] = None
        try:
            if monitor_thread and monitor_thread.is_alive():
                monitor_thread.join(timeout=1.0)
        except:
            pass
        try:
            root.quit()
            root.destroy()
        except tk.TclError:
            pass
        current_window = None

    root.protocol("WM_DELETE_WINDOW", close_window)

    for conn in connections:
        if conn["needs_resolution"]:
            Thread(
                target=resolve_hostname_async,
                args=(conn["remote_ip"], text_widget_ref, connections_ref),
                daemon=True,
            ).start()

    monitor_thread = Thread(
        target=monitor_connections, args=(text_widget_ref, connections_ref), daemon=True
    )
    monitor_thread.start()

    try:
        root.mainloop()
    except tk.TclError:
        pass

    window_open = False
    current_window = None


def quit_application(icon, item):
    """Properly quit the application"""
    global window_open, current_window

    icon.stop()

    if window_open and current_window:
        try:
            current_window.after(0, current_window.destroy)
        except:
            pass

    os._exit(0)


def create_menu():
    """Create the system tray menu"""
    return pystray.Menu(
        pystray.MenuItem("Show Connections", on_clicked, default=True),
        pystray.MenuItem(
            "Show Active Connections Only",
            toggle_view,
            checked=lambda item: SHOW_ONLY_ACTIVE,
        ),
        pystray.MenuItem("Quit", quit_application),
    )


def create_image():
    """Create tray icon"""
    return Image.open("icon.png")


def on_clicked(icon, item=None):
    """Show window on click"""
    Thread(target=show_window, daemon=True).start()


if __name__ == "__main__":
    icon = pystray.Icon("net_inspector", create_image(), menu=create_menu())
    icon.run()
