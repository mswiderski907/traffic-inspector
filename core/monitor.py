"""
Background monitoring and hostname resolution
"""

import socket
from threading import Thread, Event
import tkinter as tk
import time

from .config import hostname_cache
import core.config
from .connections import list_connections_fast

# Global monitoring control
stop_monitoring = Event()
stop_background_monitoring = Event()

# Shared connection data
current_connections = []
last_connections_update = 0


def resolve_hostname_async(ip):
    """Resolve hostname in background and update display"""
    if ip in hostname_cache:
        return

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = hostname

        # Schedule GUI update only if window is still open
        from gui.updater import gui_updater
        from gui.window import window_open

        if window_open and gui_updater.is_valid and gui_updater.text_widget:
            try:
                gui_updater.text_widget.after(0, gui_updater.safe_update_display)
            except (tk.TclError, RuntimeError, AttributeError):
                gui_updater.invalidate()

    except socket.herror:
        hostname_cache[ip] = ip
    except (tk.TclError, RuntimeError):
        pass


def monitor_connections():
    """Monitor for new connections and update display"""
    from gui.updater import gui_updater
    from gui.window import window_open

    last_connections = set()
    last_show_mode = core.config.SHOW_ONLY_ACTIVE

    while not stop_monitoring.is_set():
        try:
            if not window_open or not gui_updater.is_valid:
                break

            mode_changed = last_show_mode != core.config.SHOW_ONLY_ACTIVE
            last_show_mode = core.config.SHOW_ONLY_ACTIVE

            current_connections = list_connections_fast(core.config.SHOW_ONLY_ACTIVE)
            current_ids = {conn["id"] for conn in current_connections}

            if current_ids != last_connections or mode_changed:
                gui_updater.connections = current_connections

                # print(f"GUI monitoring: found {len(current_connections)} connections")

                # Check for new connections and send notifications (when window is open too)
                if not mode_changed:  # Only check for new connections if mode didn't change
                    new_connection_ids = current_ids - last_connections
                    if new_connection_ids:
                        new_connections = [conn for conn in current_connections if conn["id"] in new_connection_ids]
                        for conn in new_connections:
                            try:
                                from .notifications import show_connection_notification
                                show_connection_notification(conn)
                            except Exception as e:
                                print(f"Notification error: {e}")

                # Schedule GUI update
                if window_open and gui_updater.is_valid and gui_updater.text_widget:
                    try:
                        gui_updater.text_widget.after(
                            0, gui_updater.safe_update_display
                        )
                    except (tk.TclError, RuntimeError, AttributeError):
                        gui_updater.invalidate()
                        break

                # Start hostname resolution threads
                for conn in current_connections:
                    if conn["needs_resolution"]:
                        Thread(
                            target=resolve_hostname_async,
                            args=(conn["remote_ip"],),
                            daemon=True,
                        ).start()

                last_connections = current_ids

            stop_monitoring.wait(2.0)

        except (tk.TclError, RuntimeError, AttributeError):
            break
        except Exception as e:
            print(f"Error in monitor_connections: {e}")
            stop_monitoring.wait(4.0)


def background_monitor_connections():
    """Background monitoring without GUI updates - slower interval, no hostname resolution"""
    global current_connections, last_connections_update

    print("Starting background connection monitoring...")

    # Track previous connections for new connection detection
    previous_connection_ids = set()

    while not stop_background_monitoring.is_set():
        try:
            # Check window state dynamically
            from gui.window import window_open

            # Only run background monitoring when window is closed
            if not window_open:
                # Update connections every 10 seconds
                connections = list_connections_fast(core.config.SHOW_ONLY_ACTIVE)
                current_connections = connections
                last_connections_update = time.time()

                # print(f"Background monitoring: found {len(connections)} connections")

                # Check for new connections and send notifications
                current_connection_ids = {conn["id"] for conn in connections}
                new_connection_ids = current_connection_ids - previous_connection_ids

                if new_connection_ids:
                    # Find the actual new connections and check for notifications
                    new_connections = [conn for conn in connections if conn["id"] in new_connection_ids]
                    for conn in new_connections:
                        try:
                            from .notifications import show_connection_notification
                            show_connection_notification(conn)
                        except Exception as e:
                            print(f"Notification error: {e}")

                previous_connection_ids = current_connection_ids

                # Wait 10 seconds before next check
                stop_background_monitoring.wait(10.0)
            else:
                # Window is open, so GUI monitoring is handling updates
                # Just wait a bit and check again
                stop_background_monitoring.wait(2.0)

        except Exception as e:
            print(f"Error in background_monitor_connections: {e}")
            stop_background_monitoring.wait(15.0)

    print("Background connection monitoring stopped.")


def start_background_monitoring():
    """Start the background monitoring thread"""
    background_thread = Thread(target=background_monitor_connections, daemon=True)
    background_thread.start()
    return background_thread


def stop_all_monitoring():
    """Stop all monitoring threads"""
    stop_monitoring.set()
    stop_background_monitoring.set()


def get_current_connections():
    """Get the current connections from background monitoring"""
    global current_connections, last_connections_update
    return current_connections, last_connections_update
