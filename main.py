"""
Network Inspector - Main entry point
"""

import pystray
from PIL import Image
from threading import Thread
import time
import os

# TODO: Add a way to permanently save trusted connections (maybe an option to mark a connection as trusted)
# TODO: notification for new untrusted connections (must be able to mute/disable)
# TODO: make the window look better
# TODO: run on windows startup
# TODO: add a taskbar icon
# TODO: option to hide loopback addresses
# TODO: maybe an option to show where on the PC a service is running
# TODO: auto-updating list of malicious IPs that trigger notifications?
# TODO: ping active connections?

from gui.window import show_window
from core.config import SHOW_ONLY_ACTIVE


def create_menu():
    """Create the system tray menu"""
    return pystray.Menu(
        pystray.MenuItem("Show Connections", on_clicked, default=True),
        pystray.MenuItem("Quit", quit_application),
    )


def create_image():
    """Create tray icon"""
    return Image.open("icon.png")


def on_clicked(icon, item=None):
    """Show window on click"""
    Thread(target=show_window, daemon=True).start()


def quit_application(icon, item):
    """Properly quit the application"""
    from core.monitor import stop_all_monitoring
    from gui.updater import gui_updater
    from gui.window import window_open, current_window

    icon.stop()

    # Stop all monitoring and invalidate GUI updater
    stop_all_monitoring()
    gui_updater.invalidate()

    if window_open and current_window:
        try:
            current_window.after(0, current_window.destroy)
        except:
            pass

    # Give threads a moment to cleanup
    time.sleep(0.1)
    os._exit(0)


if __name__ == "__main__":
    # Start background monitoring
    from core.monitor import start_background_monitoring
    start_background_monitoring()
    
    icon = pystray.Icon("net_inspector", create_image(), menu=create_menu())
    icon.run()
