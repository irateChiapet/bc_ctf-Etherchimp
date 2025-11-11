#!/usr/bin/env ./bin/python3
import os
import sys
import argparse
import shutil
from flask import Flask
from flask_socketio import SocketIO
from backend.routes.api import register_routes

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

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='PCAP Network Visualizer')
    parser.add_argument('-f', '--file', type=str, help='PCAP file to load on startup')
    parser.add_argument('-i', '--interface', type=str, help='Network interface for live capture (e.g., eth0, en0)')
    parser.add_argument('-rhost', '--remote-host', type=str, help='Remote host for SSH capture (e.g., user@host or host)')
    parser.add_argument('-rif', '--remote-interface', type=str, help='Remote interface to capture on (required with -rhost)')
    parser.add_argument('-ruser', '--remote-user', type=str, help='SSH username for remote host (optional if specified in -rhost)')
    parser.add_argument('-rpass', '--remote-password', type=str, help='SSH password for remote host (uses sshpass)')
    parser.add_argument('-n', '--no-dns', action='store_true', help='Disable DNS name resolution for all capture modes')
    parser.add_argument('--ipv4-only', action='store_true', help='Show only IPv4 addresses (hide IPv6)')
    parser.add_argument('--private-only', action='store_true', help='Show only private/LAN addresses (hide public IPs)')
    parser.add_argument('-p', '--port', type=int, default=5001, help='Port to run server on (default: 5001)')
    args = parser.parse_args()

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

    socketio.run(app, debug=True, host='0.0.0.0', port=args.port, allow_unsafe_werkzeug=True)
