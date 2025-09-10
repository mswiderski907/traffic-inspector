"""
GUI window management
"""

import tkinter as tk
from tkinter import ttk
from threading import Thread

from core.config import toggle_show_active
import core.config
from core.connections import (
    list_connections_fast,
    format_connections,
    analyze_process_path,
)
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

                # Add process trust indicators using stored data (only if trusted)
                if core.config.is_process_trusted(conn["name"], conn["exe_path"]):
                    expected_line += " [PROCESS: TRUSTED]"

                # Add security indicators using stored path analysis
                if conn["path_analysis"] == "Suspicious":
                    expected_line += " [⚠️ SUSPICIOUS PATH]"
                elif conn["path_analysis"] == "System Process":
                    expected_line += " [🔒 SYSTEM]"

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
    details_window.geometry("600x650")
    details_window.resizable(True, True)

    # Remove modal behavior - don't grab focus
    details_window.transient(current_window)

    main_frame = tk.Frame(details_window, padx=20, pady=20)
    main_frame.pack(fill="both", expand=True)

    # Connection details
    path_analysis, path_note = connection["path_analysis"], connection["path_note"]
    details_text = f"""Process: {connection['name']}
        Process ID: {connection['pid']}
        Executable Path: {connection['exe_path']}
        Path Analysis: {path_analysis} - {path_note}
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
            f"\n\nConnection Trust Status: {'Trusted' if is_currently_trusted else 'Untrusted'}"
        )

        if user_marked:
            details_text += (
                f"\nConnection User Override: {'Trusted' if user_trust_status else 'Untrusted'}"
            )
        else:
            details_text += "\nConnection User Override: None (using default rules)"

    # Add process trust status information
    from core.config import is_process_trusted

    is_process_currently_trusted = is_process_trusted(connection["name"], connection["exe_path"])

    details_text += (
        f"\n\nProcess Trust Status: {'Trusted' if is_process_currently_trusted else 'Untrusted (default)'}"
    )

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

    # Process trust management buttons (for all connections)
    process_trust_frame = tk.Frame(main_frame)
    process_trust_frame.pack(fill="x", pady=(15, 10))

    process_trust_label = tk.Label(
        process_trust_frame, text="Mark this process as:", font=("Arial", 10, "bold")
    )
    process_trust_label.pack(anchor="w", pady=(0, 10))

    process_button_frame = tk.Frame(process_trust_frame)
    process_button_frame.pack(anchor="w")

    def mark_process_trusted_action():
        from core.config import mark_process_trusted
        mark_process_trusted(connection["name"], connection["exe_path"])
        details_window.destroy()
        refresh_connections_display()

    def remove_process_override():
        from core.config import (
            dynamic_trusted_processes,
            save_trusted_processes,
            generate_process_key,
        )
        process_key = generate_process_key(connection["name"], connection["exe_path"])
        if process_key in dynamic_trusted_processes:
            del dynamic_trusted_processes[process_key]
            save_trusted_processes()
        details_window.destroy()
        refresh_connections_display()

    process_trusted_btn = tk.Button(
        process_button_frame,
        text="Mark Process as Trusted",
        command=mark_process_trusted_action,
        bg="lightgreen",
        font=("Arial", 9),
    )
    process_trusted_btn.pack(side="left", padx=(0, 10))

    # Only show remove button if user has manually set process trust status
    if core.config.is_process_user_marked(connection["name"], connection["exe_path"]):
        process_remove_btn = tk.Button(
            process_button_frame,
            text="Remove Process Override",
            command=remove_process_override,
            bg="lightgray",
            font=("Arial", 9),
        )
        process_remove_btn.pack(side="left")

    # Network tools section (for outbound connections with remote IPs)
    if connection["remote_ip"] and connection["type"] == "Outbound":
        tools_frame = tk.Frame(main_frame)
        tools_frame.pack(fill="x", pady=(15, 10))

        tools_label = tk.Label(
            tools_frame, text="Network Tools:", font=("Arial", 10, "bold")
        )
        tools_label.pack(anchor="w", pady=(0, 10))

        tools_button_frame = tk.Frame(tools_frame)
        tools_button_frame.pack(anchor="w", pady=(0, 10))

        # Create output area for network tools
        output_frame = tk.Frame(tools_frame)
        output_frame.pack(fill="both", expand=True)

        output_text = tk.Text(
            output_frame,
            wrap="none",
            font=("Consolas", 8),
            bg="black",
            fg="white",
            height=12,
        )

        output_v_scrollbar = tk.Scrollbar(
            output_frame, orient="vertical", command=output_text.yview
        )
        output_h_scrollbar = tk.Scrollbar(
            output_frame, orient="horizontal", command=output_text.xview
        )
        output_text.configure(
            yscrollcommand=output_v_scrollbar.set, xscrollcommand=output_h_scrollbar.set
        )

        output_v_scrollbar.pack(side="right", fill="y")
        output_h_scrollbar.pack(side="bottom", fill="x")
        output_text.pack(side="left", fill="both", expand=True)

        def run_ping():
            run_network_command(
                "ping", connection["remote_ip"], output_text, tools_button_frame
            )

        def run_tracert():
            run_network_command(
                "tracert", connection["remote_ip"], output_text, tools_button_frame
            )

        ping_btn = tk.Button(
            tools_button_frame,
            text="Ping",
            command=run_ping,
            bg="lightblue",
            font=("Arial", 9),
            width=10,
        )
        ping_btn.pack(side="left", padx=(0, 10))

        tracert_btn = tk.Button(
            tools_button_frame,
            text="Tracert",
            command=run_tracert,
            bg="lightyellow",
            font=("Arial", 9),
            width=10,
        )
        tracert_btn.pack(side="left", padx=(0, 10))

        clear_btn = tk.Button(
            tools_button_frame,
            text="Clear Output",
            command=lambda: output_text.delete("1.0", tk.END),
            bg="lightgray",
            font=("Arial", 9),
            width=12,
        )
        clear_btn.pack(side="left")

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


def run_network_command(tool, target_ip, output_text, button_frame):
    """Run ping or tracert and display results in the provided text widget"""
    import subprocess
    import platform
    from threading import Thread

    def disable_buttons():
        """Disable network tool buttons while command is running"""
        for widget in button_frame.winfo_children():
            if isinstance(widget, tk.Button) and widget["text"] in ["Ping", "Tracert"]:
                widget.config(state="disabled")

    def enable_buttons():
        """Re-enable network tool buttons after command completes"""
        for widget in button_frame.winfo_children():
            if isinstance(widget, tk.Button) and widget["text"] in ["Ping", "Tracert"]:
                widget.config(state="normal")

    def run_command():
        """Run the network command in a separate thread"""
        try:
            # Disable buttons while running
            output_text.after(0, disable_buttons)

            # Clear previous output and add header
            def add_header():
                output_text.delete("1.0", tk.END)
                output_text.insert(
                    tk.END, f"Running {tool.upper()} to {target_ip}...\n\n"
                )
                output_text.see(tk.END)

            output_text.after(0, add_header)

            # Determine the correct command based on OS
            system = platform.system().lower()

            cmd = None
            if tool == "ping":
                if system == "windows":
                    cmd = ["ping", "-n", "4", target_ip]
                else:
                    cmd = ["ping", "-c", "4", target_ip]
            elif tool == "tracert":
                if system == "windows":
                    cmd = ["tracert", target_ip]
                else:
                    cmd = ["traceroute", target_ip]

            # Run the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
            )

            # Read output line by line and update the display
            def update_output(line):
                try:
                    output_text.insert(tk.END, line)
                    output_text.see(tk.END)  # Auto-scroll to bottom
                except tk.TclError:
                    pass

            for line in process.stdout:
                output_text.after(0, lambda l=line: update_output(l))

            process.wait()

            # Add completion message
            def add_completion():
                if process.returncode == 0:
                    output_text.insert(
                        tk.END, f"\n{tool.upper()} completed successfully.\n"
                    )
                else:
                    output_text.insert(
                        tk.END,
                        f"\n{tool.upper()} completed with errors (return code: {process.returncode}).\n",
                    )
                output_text.see(tk.END)
                enable_buttons()

            output_text.after(0, add_completion)

        except FileNotFoundError:

            def show_error():
                output_text.delete("1.0", tk.END)
                output_text.insert(
                    tk.END, f"Error: {tool} command not found on this system.\n"
                )
                output_text.insert(
                    tk.END, f"Make sure {tool} is installed and available in PATH.\n"
                )
                enable_buttons()

            output_text.after(0, show_error)

        except Exception as e:

            def show_error():
                output_text.delete("1.0", tk.END)
                output_text.insert(tk.END, f"Error running {tool}: {str(e)}\n")
                enable_buttons()

            output_text.after(0, show_error)

    # Start the command in a background thread
    Thread(target=run_command, daemon=True).start()
