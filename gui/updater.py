"""
Thread-safe GUI updater
"""

import tkinter as tk
from threading import Event

from core.config import hostname_cache
import core.config
from core.connections import format_connections


class SafeGUIUpdater:
    """Thread-safe GUI updater that prevents crashes when window is closed"""

    def __init__(self):
        self.text_widget = None
        self.connections = None
        self.view_dropdown = None
        self.is_valid = True
        self._lock = Event()
        self._lock.set()

    def set_widgets(self, text_widget, connections, view_dropdown):
        """Set the GUI widgets to update"""
        self.text_widget = text_widget
        self.connections = connections
        self.view_dropdown = view_dropdown
        self.is_valid = True

    def invalidate(self):
        """Mark this updater as invalid (window closed)"""
        self.is_valid = False
        self.text_widget = None
        self.connections = None
        self.view_dropdown = None

    def safe_update_display(self):
        """Safely update display from cache"""
        if not self.is_valid:
            return

        from gui.window import window_open

        if not window_open:
            return

        try:
            if not self.text_widget or not self.text_widget.winfo_exists():
                return

            scroll_y = self.text_widget.yview()
            scroll_x = self.text_widget.xview()

            # Update dropdown to reflect current setting
            if self.view_dropdown and self.view_dropdown.winfo_exists():
                current_value = (
                    "Active Connections Only"
                    if core.config.SHOW_ONLY_ACTIVE
                    else "All Connections"
                )
                if self.view_dropdown.get() != current_value:
                    self.view_dropdown.set(current_value)

            # Update connections with resolved hostnames
            for conn in self.connections:
                if conn["remote_ip"] and conn["remote_ip"] in hostname_cache:
                    resolved_host = hostname_cache[conn["remote_ip"]]
                    if resolved_host != conn["remote_host"]:
                        conn["remote_host"] = resolved_host
                        conn["raddr"] = (
                            f"{resolved_host} ({conn['remote_ip']}):{conn['raddr'].split(':')[-1]}"
                        )
                        conn["needs_resolution"] = False

            self.text_widget.delete("1.0", tk.END)
            self.text_widget.insert("1.0", format_connections(self.connections))

            self.text_widget.yview_moveto(scroll_y[0])
            self.text_widget.xview_moveto(scroll_x[0])

        except (tk.TclError, RuntimeError, AttributeError):
            # Widget no longer exists, mark as invalid
            self.invalidate()


# Global GUI updater instance
gui_updater = SafeGUIUpdater()
