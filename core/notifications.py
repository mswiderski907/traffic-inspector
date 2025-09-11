"""
Windows notification system for Traffic Inspector
"""

import time
from threading import Lock
from plyer import notification
from .config import NOTIFICATION_SETTINGS, is_process_trusted

# Notification throttling - prevent spam
notification_cache = {}
notification_lock = Lock()
NOTIFICATION_COOLDOWN = 300  # 5 minutes between same notifications


def should_notify_for_connection(connection):
    """Determine if we should notify for this connection based on settings"""
    if not NOTIFICATION_SETTINGS.get("enabled", True):
        return False

    mode = NOTIFICATION_SETTINGS.get("mode", "none")

    if mode == "none":
        return False
    elif mode == "untrusted_processes":
        # Notify for any connection from an untrusted process
        return not is_process_trusted(connection["name"], connection["exe_path"])
    elif mode == "high_risk":
        # Notify for suspicious paths or untrusted processes to external IPs
        if connection["path_analysis"] == "Suspicious":
            return True
        if (
            not is_process_trusted(connection["name"], connection["exe_path"])
            and connection["remote_ip"]
            and connection["type"] == "Outbound"
        ):
            return True

    return False


def get_notification_key(connection):
    """Generate a unique key for notification throttling"""
    # Group by process + remote host to avoid spam
    return f"{connection['name']}_{connection['exe_path']}_{connection.get('remote_ip', 'local')}"


def show_connection_notification(connection):
    """Show a Windows toast notification for a connection"""
    if not should_notify_for_connection(connection):
        return

    # Check throttling
    notification_key = get_notification_key(connection)
    current_time = time.time()

    with notification_lock:
        last_notification = notification_cache.get(notification_key, 0)
        if current_time - last_notification < NOTIFICATION_COOLDOWN:
            return  # Too soon, skip notification

        notification_cache[notification_key] = current_time

    # Clean old entries from cache
    cleanup_notification_cache()

    # Prepare notification content
    process_name = connection["name"]
    remote_info = connection.get("raddr", "Unknown")
    if connection.get("remote_ip"):
        remote_info = f"{connection['remote_host']} ({connection['remote_ip']})"

    title = "Untrusted Process Connection"

    if connection["type"] == "Outbound":
        message = f"{process_name} connected to {remote_info}"
    else:
        message = f"{process_name} is listening on {connection['laddr']}"

    # Add risk indicators
    if connection["path_analysis"] == "Suspicious":
        title = "⚠️ Suspicious Process Connection"
        message += "\n⚠️ Process running from suspicious location"

    try:
        notification.notify(
            title=title,
            message=message,
            app_name="Traffic Inspector",
            timeout=8,  # Show for 8 seconds
            app_icon=None,  # Could add icon path here
        )

        print(f"Notification sent: {title} - {message}")

    except Exception as e:
        print(f"Failed to send notification: {e}")


def cleanup_notification_cache():
    """Remove old entries from notification cache"""
    current_time = time.time()
    cutoff_time = current_time - (
        NOTIFICATION_COOLDOWN * 2
    )  # Keep entries for 2x cooldown

    with notification_lock:
        keys_to_remove = [
            key
            for key, timestamp in notification_cache.items()
            if timestamp < cutoff_time
        ]
        for key in keys_to_remove:
            del notification_cache[key]


def test_notification():
    """Test function to show a sample notification"""
    try:
        notification.notify(
            title="Traffic Inspector Test",
            message="Notification system is working!",
            app_name="Traffic Inspector",
            timeout=5,
        )
        print("Test notification sent successfully")
        return True
    except Exception as e:
        print(f"Test notification failed: {e}")
        return False
