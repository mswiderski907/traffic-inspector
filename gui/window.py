"""
GUI window management
"""

import tkinter as tk
from tkinter import ttk
from threading import Thread

from core.config import toggle_show_active
import core.config
from core.connections import list_connections_fast, format_connections
from core.monitor import monitor_connections, stop_monitoring, resolve_hostname_async
from .updater import gui_updater

# Global window state
window_open = False
current_window = None
monitor_thread = None


def show_window():
    """Display connections window"""
    global window_open, current_window, monitor_thread

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
    current_window = root

    frame = tk.Frame(root)
    frame.pack(fill="both", expand=True, padx=5, pady=5)

    # Create dropdown frame for view selection
    dropdown_frame = tk.Frame(frame, bg="lightgray")
    dropdown_frame.pack(fill="x", pady=(0, 5))

    view_label = tk.Label(
        dropdown_frame, text="View:", font=("Consolas", 9), bg="lightgray"
    )
    view_label.pack(side="left", padx=(5, 5))

    # Create dropdown with view options
    view_var = tk.StringVar()
    view_options = ["Active Connections Only", "All Connections"]
    view_var.set(view_options[0] if core.config.SHOW_ONLY_ACTIVE else view_options[1])

    def on_view_change(*args):
        """Handle view selection change"""
        selected = view_var.get()
        current_active_setting = selected == "Active Connections Only"

        # Only toggle if the setting actually changed
        if current_active_setting != core.config.SHOW_ONLY_ACTIVE:
            toggle_show_active()
            # The monitor thread will detect the change and update the display
            refresh_connections_display()

    view_dropdown = ttk.Combobox(
        dropdown_frame,
        textvariable=view_var,
        values=view_options,
        state="readonly",
        width=25,
        font=("Consolas", 9),
    )
    view_dropdown.pack(side="left", padx=(0, 5))
    view_dropdown.bind("<<ComboboxSelected>>", on_view_change)

    def refresh_connections_display():
        """Manually refresh the connections display"""
        try:
            scroll_y = text.yview()
            scroll_x = text.xview()

            new_connections = list_connections_fast(core.config.SHOW_ONLY_ACTIVE)
            gui_updater.connections = new_connections

            if text and text.winfo_exists():
                text.delete("1.0", tk.END)
                text.insert("1.0", format_connections(new_connections))

                text.yview_moveto(scroll_y[0])
                text.xview_moveto(scroll_x[0])

                # Start hostname resolution for new connections that need it
                for conn in new_connections:
                    if conn["needs_resolution"]:
                        Thread(
                            target=resolve_hostname_async,
                            args=(conn["remote_ip"],),
                            daemon=True,
                        ).start()
        except (tk.TclError, AttributeError):
            pass

    text = tk.Text(frame, wrap="none", font=("consolas", 9))

    v_scrollbar = tk.Scrollbar(frame, orient="vertical", command=text.yview)
    h_scrollbar = tk.Scrollbar(frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

    v_scrollbar.pack(side="right", fill="y")
    h_scrollbar.pack(side="bottom", fill="x")
    text.pack(side="left", fill="both", expand=True)

    connections = list_connections_fast(core.config.SHOW_ONLY_ACTIVE)

    # Set up the GUI updater with current widgets (pass dropdown instead of status label)
    gui_updater.set_widgets(text, connections, view_dropdown)

    text.insert("1.0", format_connections(connections))

    def close_window():
        global window_open, current_window, monitor_thread
        window_open = False

        # Invalidate GUI updater to prevent further updates
        gui_updater.invalidate()

        # Stop monitoring thread
        stop_monitoring.set()

        # Wait for monitor thread to finish
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=1.0)

        try:
            root.quit()
            root.destroy()
        except tk.TclError:
            pass

        current_window = None

    root.protocol("WM_DELETE_WINDOW", close_window)

    # Start hostname resolution for initial connections
    for conn in connections:
        if conn["needs_resolution"]:
            Thread(
                target=resolve_hostname_async,
                args=(conn["remote_ip"],),
                daemon=True,
            ).start()

    # Start monitoring thread
    monitor_thread = Thread(target=monitor_connections, daemon=True)
    monitor_thread.start()

    try:
        root.mainloop()
    except tk.TclError:
        pass

    # Cleanup after mainloop exits
    window_open = False
    gui_updater.invalidate()
    current_window = None
