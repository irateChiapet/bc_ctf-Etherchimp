#!/usr/bin/env ./bin/python3
import os
import sys
import argparse
import shutil
import signal
import logging
from datetime import datetime
from flask import Flask
from flask_socketio import SocketIO
from backend.routes.api import register_routes
from backend.utils.log_cleanup import LogCleanupService

# Initialize Flask App
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'pcap_visualizer_secret'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Register routes
register_routes(app, socketio)

# Daemon configuration
PID_FILE = '/tmp/etherchimp.pid'
LOG_FILE = '/tmp/etherchimp.log'

# Global cleanup service instance
cleanup_service = None

def setup_logging(to_file=False):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if to_file:
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)
    return logging.getLogger(__name__)

def handle_sighup(signum, frame):
    """Handle SIGHUP signal for system reload."""
    logger = logging.getLogger(__name__)
    logger.info("Received SIGHUP signal - reloading system")

    global cleanup_service

    # Stop cleanup service if running
    if cleanup_service:
        cleanup_service.stop()

    # Restart the daemon process
    logger.info("Restarting daemon process...")
    python = sys.executable
    os.execv(python, [python] + sys.argv)

def is_daemon_running():
    """Check if daemon is already running"""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            # Check if process is actually running
            os.kill(pid, 0)
            return True, pid
        except (OSError, ValueError):
            # PID file exists but process is not running
            os.remove(PID_FILE)
            return False, None
    return False, None

def start_daemon(args_list):
    """Start the application as a daemon"""
    running, pid = is_daemon_running()
    if running:
        print(f"Daemon is already running with PID {pid}")
        return False

    # Fork the process
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process
            print(f"Daemon started with PID {pid}")
            print(f"Logs are being written to: {LOG_FILE}")
            print(f"Use 'python app.py -l' to view logs")
            print(f"Use 'python app.py --stop' to stop the daemon")
            sys.exit(0)
    except OSError as e:
        print(f"Fork failed: {e}")
        sys.exit(1)

    # Child process continues here
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    # Second fork to prevent zombie processes
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Second fork failed: {e}")
        sys.exit(1)

    # Write PID file
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()

    # Redirect stdin, stdout, stderr to log file
    with open(LOG_FILE, 'a') as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())

    return True

def stop_daemon():
    """Stop the daemon process"""
    running, pid = is_daemon_running()
    if not running:
        print("Daemon is not running")
        return False

    try:
        print(f"Stopping daemon with PID {pid}...")
        os.kill(pid, signal.SIGTERM)
        # Wait a moment for graceful shutdown
        import time
        time.sleep(1)

        # Check if still running
        try:
            os.kill(pid, 0)
            print("Daemon did not stop gracefully, forcing...")
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        print("Daemon stopped successfully")
        return True
    except OSError as e:
        print(f"Failed to stop daemon: {e}")
        return False

def view_logs(follow=False):
    """View daemon logs"""
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        return

    if follow:
        print(f"Following logs from {LOG_FILE} (Ctrl+C to stop)...")
        try:
            import subprocess
            subprocess.run(['tail', '-f', LOG_FILE])
        except KeyboardInterrupt:
            print("\nStopped following logs")
    else:
        print(f"Last 50 lines from {LOG_FILE}:")
        print("-" * 80)
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                for line in lines[-50:]:
                    print(line.rstrip())
        except Exception as e:
            print(f"Error reading log file: {e}")

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='PCAP Network Visualizer')

    # Daemon control options
    parser.add_argument('--daemon', action='store_true', help='Run application as a daemon in the background')
    parser.add_argument('-l', '--logs', action='store_true', help='View daemon logs (last 50 lines)')
    parser.add_argument('--follow', action='store_true', help='Follow daemon logs in real-time (use with -l)')
    parser.add_argument('--stop', action='store_true', help='Stop the running daemon')
    parser.add_argument('--status', action='store_true', help='Check daemon status')

    # Application options
    parser.add_argument('-f', '--file', type=str, help='PCAP file to load on startup')
    parser.add_argument('-i', '--interface', type=str, help='Network interface for live capture (e.g., eth0, en0)')
    parser.add_argument('-rhost', '--remote-host', type=str, help='Remote host for SSH capture (e.g., user@host or host)')
    parser.add_argument('-rif', '--remote-interface', type=str, help='Remote interface to capture on (required with -rhost)')
    parser.add_argument('-ruser', '--remote-user', type=str, help='SSH username for remote host (optional if specified in -rhost)')
    parser.add_argument('-rpass', '--remote-password', type=str, help='SSH password for remote host (uses sshpass)')
    parser.add_argument('-n', '--no-dns', action='store_true', help='Disable DNS name resolution for all capture modes')
    parser.add_argument('--ipv4-only', action='store_true', help='Show only IPv4 addresses (hide IPv6)')
    parser.add_argument('--private-only', action='store_true', help='Show only private/LAN addresses (hide public IPs)')
    parser.add_argument('--no-upload', action='store_true', help='Disable upload and enable download of captured PCAP files')
    parser.add_argument('-p', '--port', type=int, default=5001, help='Port to run server on (default: 5001)')
    args = parser.parse_args()

    # Handle daemon control commands
    if args.stop:
        stop_daemon()
        sys.exit(0)

    if args.status:
        running, pid = is_daemon_running()
        if running:
            print(f"Daemon is running with PID {pid}")
        else:
            print("Daemon is not running")
        sys.exit(0)

    if args.logs:
        view_logs(follow=args.follow)
        sys.exit(0)

    # Start as daemon if requested
    is_daemon = False
    if args.daemon:
        # Need to return to original directory for app to work
        original_dir = os.getcwd()
        if start_daemon(sys.argv):
            # We're in the daemon process now
            os.chdir(original_dir)
            setup_logging(to_file=True)
            is_daemon = True
        else:
            sys.exit(1)

    # Check for conflicting arguments
    if sum([bool(args.file), bool(args.interface), bool(args.remote_host)]) > 1:
        print("Error: Cannot use -f (file), -i (interface), and -rhost (remote host) together")
        sys.exit(1)

    # Check remote host requirements
    if args.remote_host and not args.remote_interface:
        print("Error: -rhost requires -rif (remote interface)")
        sys.exit(1)
    if args.remote_interface and not args.remote_host:
        print("Error: -rif requires -rhost (remote host)")
        sys.exit(1)

    # If a file is specified, copy it to uploads folder
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)

        if not (args.file.endswith('.pcap') or args.file.endswith('.pcapng')):
            print(f"Error: File must be .pcap or .pcapng format")
            sys.exit(1)

        # Copy file to uploads folder with a known name
        dest_path = os.path.join(UPLOAD_FOLDER, 'autoload.pcap')
        shutil.copy2(args.file, dest_path)
        app.config['AUTOLOAD_FILE'] = 'autoload.pcap'
        print(f"Auto-loading PCAP file: {args.file}")

    # Set DNS resolution flag
    app.config['NO_DNS'] = args.no_dns
    if args.no_dns:
        print("DNS resolution disabled (-n flag)")

    # Set IP filtering flags
    app.config['IPV4_ONLY'] = args.ipv4_only
    app.config['PRIVATE_ONLY'] = args.private_only
    if args.ipv4_only:
        print("IPv4-only mode enabled (IPv6 addresses will be hidden)")
    if args.private_only:
        print("Private-only mode enabled (Public IP addresses will be hidden)")

    # Set no-upload mode
    app.config['NO_UPLOAD'] = args.no_upload
    if args.no_upload:
        print("Upload disabled - Download mode enabled for captured PCAP files")

    # If an interface is specified, set up live capture
    if args.interface:
        app.config['LIVE_INTERFACE'] = args.interface
        app.config['CAPTURE_MODE'] = 'local'
        print(f"Starting live capture on interface: {args.interface}")
        print("Note: May require sudo/admin privileges for packet capture")

    # If remote host is specified, set up remote capture
    if args.remote_host:
        app.config['REMOTE_HOST'] = args.remote_host
        app.config['REMOTE_INTERFACE'] = args.remote_interface
        app.config['REMOTE_USER'] = args.remote_user
        app.config['REMOTE_PASSWORD'] = args.remote_password
        app.config['CAPTURE_MODE'] = 'remote'
        print(f"Starting remote capture on {args.remote_host}:{args.remote_interface}")
        print("Note: Requires SSH access and sudo privileges on remote host")
        if args.remote_password:
            print("Using password authentication (requires sshpass installed)")
        else:
            print("Using SSH key authentication")

    # Start log cleanup service in daemon mode only
    if is_daemon:
        logger = logging.getLogger(__name__)
        logger.info("Starting log cleanup service (7 minute retention)")

        # Register SIGHUP handler for system reload
        signal.signal(signal.SIGHUP, handle_sighup)

        # Start cleanup service
        cleanup_service = LogCleanupService(
            upload_folder=UPLOAD_FOLDER,
            retention_minutes=7,
            check_interval=60  # Check every minute
        )
        cleanup_service.start()

    # Disable debug mode when running as daemon (debug mode's reloader conflicts with daemon)
    socketio.run(app, debug=(not is_daemon), host='0.0.0.0', port=args.port, allow_unsafe_werkzeug=True)
