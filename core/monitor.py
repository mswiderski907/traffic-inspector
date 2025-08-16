"""
Background monitoring and hostname resolution
"""

import socket
from threading import Thread, Event
import tkinter as tk

from .config import hostname_cache
import core.config
from .connections import list_connections_fast

# Global monitoring control
stop_monitoring = Event()


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
