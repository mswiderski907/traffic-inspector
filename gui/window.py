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


def refresh_connections_display():
    """Refresh the connections display while preserving scroll position"""
    if not window_open or not gui_updater.is_valid or not gui_updater.text_widget:
        return

    try:
        text_widget = gui_updater.text_widget

        # Save current scroll position
        scroll_y = text_widget.yview()
        scroll_x = text_widget.xview()

        new_connections = list_connections_fast(core.config.SHOW_ONLY_ACTIVE)
        gui_updater.connections = new_connections

        if text_widget and text_widget.winfo_exists():
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", format_connections(new_connections))

            # Restore scroll position
            text_widget.yview_moveto(scroll_y[0])
            text_widget.xview_moveto(scroll_x[0])

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

    # Add instructions
    instructions_label = tk.Label(
        dropdown_frame,
        text="Double-click any connection for details",
        font=("Consolas", 8),
        bg="lightgray",
        fg="gray",
    )
    instructions_label.pack(side="right", padx=(5, 5))

    text = tk.Text(frame, wrap="none", font=("consolas", 9))

    v_scrollbar = tk.Scrollbar(frame, orient="vertical", command=text.yview)
    h_scrollbar = tk.Scrollbar(frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

    v_scrollbar.pack(side="right", fill="y")
    h_scrollbar.pack(side="bottom", fill="x")
    text.pack(side="left", fill="both", expand=True)

    def on_text_double_click(event):
        """Handle double-click on text widget to show connection details"""
        try:
            # Get the line that was clicked
            click_index = text.index(f"@{event.x},{event.y}")
            line_start = click_index.split(".")[0] + ".0"
            line_end = click_index.split(".")[0] + ".end"
            clicked_line = text.get(line_start, line_end).strip()

            # Skip empty lines and section headers
            if not clicked_line or clicked_line.startswith("===") or not clicked_line:
                return

            # Find the connection that matches this line
            for conn in gui_updater.connections:
                # Build the expected line (same as in format_connections)
                base_line = f"{conn['name']:<25} PID: {conn['pid']:<6} Local: {conn['laddr']:<21} Remote: {conn['raddr']}"

                # Add trust status indicators if applicable
                expected_line = base_line
                if conn["remote_ip"] and core.config.is_connection_user_marked(
                    conn["remote_ip"]
                ):
                    user_trust = core.config.get_connection_trust_status(
                        conn["remote_ip"]
                    )
                    if user_trust:
                        expected_line += " [USER: TRUSTED]"
                    else:
                        expected_line += " [USER: UNTRUSTED]"

                if clicked_line == expected_line:
                    show_connection_details(conn)
                    break
        except (tk.TclError, IndexError):
            pass

    # Bind double-click event
    text.bind("<Double-Button-1>", on_text_double_click)

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


def show_connection_details(connection):
    """Show detailed information about a connection in a popup window"""
    details_window = tk.Toplevel()
    details_window.title(f"Connection Details - {connection['name']}")
    details_window.geometry("500x400")
    details_window.resizable(False, False)

    # Make window modal
    details_window.transient(current_window)
    details_window.grab_set()

    main_frame = tk.Frame(details_window, padx=20, pady=20)
    main_frame.pack(fill="both", expand=True)

    # Connection details
    details_text = f"""Process: {connection['name']}
        Process ID: {connection['pid']}
        Local Address: {connection['laddr']}
        Remote Address: {connection['raddr']}
        Status: {connection['status']}
        Connection Type: {connection['type']}"""

    if connection["remote_ip"]:
        details_text += f"\nRemote IP: {connection['remote_ip']}"
        if connection["remote_host"] != connection["remote_ip"]:
            details_text += f"\nResolved Hostname: {connection['remote_host']}"

    # Add trust status information
    if connection["remote_ip"]:
        from core.config import (
            is_trusted,
            is_connection_user_marked,
            get_connection_trust_status,
        )

        is_currently_trusted = is_trusted(
            connection["remote_ip"], connection["remote_host"]
        )
        user_marked = is_connection_user_marked(connection["remote_ip"])
        user_trust_status = get_connection_trust_status(connection["remote_ip"])

        details_text += (
            f"\n\nTrust Status: {'Trusted' if is_currently_trusted else 'Untrusted'}"
        )

        if user_marked:
            details_text += (
                f"\nUser Override: {'Trusted' if user_trust_status else 'Untrusted'}"
            )
        else:
            details_text += "\nUser Override: None (using default rules)"

    # Details display
    details_label = tk.Label(
        main_frame,
        text=details_text,
        font=("Consolas", 10),
        justify="left",
        anchor="nw",
    )
    details_label.pack(anchor="w", pady=(0, 20))

    # Trust management buttons (only for outbound connections with remote IPs)
    if connection["remote_ip"] and connection["type"] == "Outbound":
        trust_frame = tk.Frame(main_frame)
        trust_frame.pack(fill="x", pady=(0, 10))

        trust_label = tk.Label(
            trust_frame, text="Mark this connection as:", font=("Arial", 10, "bold")
        )
        trust_label.pack(anchor="w", pady=(0, 10))

        button_frame = tk.Frame(trust_frame)
        button_frame.pack(anchor="w")

        def mark_trusted():
            from core.config import mark_connection_trusted

            mark_connection_trusted(
                connection["remote_ip"], connection["remote_host"], True
            )
            details_window.destroy()
            # Refresh main window to show updated trust status
            refresh_connections_display()

        def mark_untrusted():
            from core.config import mark_connection_trusted

            mark_connection_trusted(
                connection["remote_ip"], connection["remote_host"], False
            )
            details_window.destroy()
            # Refresh main window to show updated trust status
            refresh_connections_display()

        def remove_override():
            from core.config import (
                dynamic_trusted_connections,
                save_trusted_connections,
            )

            if connection["remote_ip"] in dynamic_trusted_connections:
                del dynamic_trusted_connections[connection["remote_ip"]]
                save_trusted_connections()
            details_window.destroy()
            # Refresh main window to show updated trust status
            refresh_connections_display()

        trusted_btn = tk.Button(
            button_frame,
            text="Mark as Trusted",
            command=mark_trusted,
            bg="lightgreen",
            font=("Arial", 9),
        )
        trusted_btn.pack(side="left", padx=(0, 10))

        untrusted_btn = tk.Button(
            button_frame,
            text="Mark as Untrusted",
            command=mark_untrusted,
            bg="lightcoral",
            font=("Arial", 9),
        )
        untrusted_btn.pack(side="left", padx=(0, 10))

        # Only show remove button if user has manually set trust status
        if is_connection_user_marked(connection["remote_ip"]):
            remove_btn = tk.Button(
                button_frame,
                text="Remove Override",
                command=remove_override,
                bg="lightgray",
                font=("Arial", 9),
            )
            remove_btn.pack(side="left")

    # Close button
    close_frame = tk.Frame(main_frame)
    close_frame.pack(fill="x", pady=(10, 0))

    close_btn = tk.Button(
        close_frame, text="Close", command=details_window.destroy, font=("Arial", 10)
    )
    close_btn.pack(anchor="center")

    # Center the window
    details_window.update_idletasks()
    x = (details_window.winfo_screenwidth() // 2) - (details_window.winfo_width() // 2)
    y = (details_window.winfo_screenheight() // 2) - (
        details_window.winfo_height() // 2
    )
    details_window.geometry(f"+{x}+{y}")

    # Focus the window
    details_window.focus_set()
