"""Flask routes for the PCAP Analyzer API."""

import os
from flask import request, jsonify, render_template
from werkzeug.utils import secure_filename
from backend.processing.pcap_processor import process_pcap
from backend.processing.live_capture import LiveCapture
from backend.processing.remote_capture import RemoteCapture

# Global live capture instance
live_capture_instance = None


def register_routes(app, socketio=None):
    """Register all routes with the Flask app."""

    @app.route('/')
    def index():
        """Serves the main HTML file."""
        autoload_file = app.config.get('AUTOLOAD_FILE', None)
        return render_template('run.html', autoload_file=autoload_file)

    @app.route('/test-search')
    def test_search():
        """Serves the search test page."""
        with open('test_search.html', 'r') as f:
            return f.read()

    @app.route('/debug-search')
    def debug_search():
        """Serves the search debug page."""
        with open('debug_search.html', 'r') as f:
            return f.read()

    @app.route('/autoload', methods=['GET'])
    def autoload():
        """Check if there's a file to autoload."""
        autoload_file = app.config.get('AUTOLOAD_FILE', None)
        if autoload_file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], autoload_file)
            if os.path.exists(filepath):
                # Process the autoloaded file with DNS resolution and IP filter settings
                no_dns = app.config.get('NO_DNS', False)
                ipv4_only = app.config.get('IPV4_ONLY', False)
                private_only = app.config.get('PRIVATE_ONLY', False)
                data = process_pcap(filepath, no_dns=no_dns, ipv4_only=ipv4_only, private_only=private_only)
                if 'error' in data:
                    return jsonify({'error': data['error']}), 500
                return jsonify(data)
        return jsonify({'autoload': False})

    @app.route('/upload', methods=['POST'])
    def upload_file():
        """Handles PCAP file upload and processing."""
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Process the file and get the data with DNS resolution and IP filter settings
            no_dns = app.config.get('NO_DNS', False)
            ipv4_only = app.config.get('IPV4_ONLY', False)
            private_only = app.config.get('PRIVATE_ONLY', False)
            data = process_pcap(filepath, no_dns=no_dns, ipv4_only=ipv4_only, private_only=private_only)

            # Keep the uploaded file in ./uploads directory for reference
            # Do NOT delete it

            if 'error' in data:
                return jsonify(data), 500

            return jsonify(data)

    # SocketIO event handlers for live capture
    if socketio:
        @socketio.on('start_capture')
        def handle_start_capture(data):
            """Start live packet capture (local or remote)."""
            global live_capture_instance

            print("[Backend] Received start_capture event")

            # Check capture mode
            capture_mode = app.config.get('CAPTURE_MODE', 'local')

            if capture_mode == 'remote':
                # Remote capture mode
                remote_host = app.config.get('REMOTE_HOST')
                remote_interface = app.config.get('REMOTE_INTERFACE')
                remote_user = app.config.get('REMOTE_USER')
                remote_password = app.config.get('REMOTE_PASSWORD')

                if not remote_host or not remote_interface:
                    print("[Backend] No remote host/interface configured")
                    socketio.emit('capture_error', {'error': 'No remote host/interface specified'})
                    return

                print(f"[Backend] Starting remote capture on {remote_host}:{remote_interface}")

                # Stop existing capture if running
                if live_capture_instance and live_capture_instance.running:
                    print("[Backend] Stopping existing capture")
                    live_capture_instance.stop()

                # Start new remote capture
                no_dns = app.config.get('NO_DNS', False)
                ipv4_only = app.config.get('IPV4_ONLY', False)
                private_only = app.config.get('PRIVATE_ONLY', False)
                live_capture_instance = RemoteCapture(
                    remote_host,
                    remote_interface,
                    socketio,
                    app.config['UPLOAD_FOLDER'],
                    username=remote_user,
                    password=remote_password,
                    no_dns=no_dns,
                    ipv4_only=ipv4_only,
                    private_only=private_only
                )
                live_capture_instance.start()
                print("[Backend] Remote capture started, emitting capture_started event")
                socketio.emit('capture_started', {'interface': f"{remote_host}:{remote_interface}"})

            else:
                # Local capture mode
                interface = app.config.get('LIVE_INTERFACE')
                if not interface:
                    print("[Backend] No interface configured")
                    socketio.emit('capture_error', {'error': 'No interface specified'})
                    return

                print(f"[Backend] Starting capture on interface: {interface}")

                # Stop existing capture if running
                if live_capture_instance and live_capture_instance.running:
                    print("[Backend] Stopping existing capture")
                    live_capture_instance.stop()

                # Start new capture
                no_dns = app.config.get('NO_DNS', False)
                ipv4_only = app.config.get('IPV4_ONLY', False)
                private_only = app.config.get('PRIVATE_ONLY', False)
                live_capture_instance = LiveCapture(interface, socketio, app.config['UPLOAD_FOLDER'],
                                                   no_dns=no_dns, ipv4_only=ipv4_only, private_only=private_only)
                live_capture_instance.start()
                print("[Backend] Capture started, emitting capture_started event")
                socketio.emit('capture_started', {'interface': interface})

        @socketio.on('stop_capture')
        def handle_stop_capture():
            """Stop live packet capture."""
            global live_capture_instance

            if live_capture_instance:
                live_capture_instance.stop()
                socketio.emit('capture_stopped', {})

        @socketio.on('save_and_restart_capture')
        def handle_save_and_restart(data=None):
            """Save current capture to file and start a new capture session."""
            global live_capture_instance

            if not live_capture_instance:
                socketio.emit('capture_error', {'error': 'No active capture to save'})
                return

            print("[Backend] Saving and restarting capture")

            # Save current capture (this happens automatically in stop())
            live_capture_instance.stop()

            # Wait briefly for save to complete
            import time
            time.sleep(0.5)

            # Start new capture session based on mode
            capture_mode = app.config.get('CAPTURE_MODE', 'local')

            if capture_mode == 'remote':
                # Remote capture restart
                remote_host = app.config.get('REMOTE_HOST')
                remote_interface = app.config.get('REMOTE_INTERFACE')
                remote_user = app.config.get('REMOTE_USER')
                remote_password = app.config.get('REMOTE_PASSWORD')

                if remote_host and remote_interface:
                    no_dns = app.config.get('NO_DNS', False)
                    live_capture_instance = RemoteCapture(
                        remote_host,
                        remote_interface,
                        socketio,
                        app.config['UPLOAD_FOLDER'],
                        username=remote_user,
                        password=remote_password,
                        no_dns=no_dns
                    )
                    live_capture_instance.start()
                    socketio.emit('capture_restarted', {'interface': f"{remote_host}:{remote_interface}"})
                    print("[Backend] Remote capture saved and restarted")
                else:
                    socketio.emit('capture_error', {'error': 'No remote host/interface configured for restart'})
            else:
                # Local capture restart
                interface = app.config.get('LIVE_INTERFACE')
                if interface:
                    no_dns = app.config.get('NO_DNS', False)
                    live_capture_instance = LiveCapture(interface, socketio, app.config['UPLOAD_FOLDER'], no_dns=no_dns)
                    live_capture_instance.start()
                    socketio.emit('capture_restarted', {'interface': interface})
                    print("[Backend] Local capture saved and restarted")
                else:
                    socketio.emit('capture_error', {'error': 'No interface configured for restart'})

        @socketio.on('connect')
        def handle_connect():
            """Handle client connection."""
            global live_capture_instance
            print("[Backend] Client connected to WebSocket")

            # Check if any capture interface is configured
            capture_mode = app.config.get('CAPTURE_MODE')
            interface = None

            if capture_mode == 'remote':
                remote_host = app.config.get('REMOTE_HOST')
                remote_interface = app.config.get('REMOTE_INTERFACE')
                if remote_host and remote_interface:
                    interface = f"{remote_host}:{remote_interface}"
            elif capture_mode == 'local':
                interface = app.config.get('LIVE_INTERFACE')

            if interface:
                # Check if capture is already running
                if live_capture_instance and live_capture_instance.running:
                    print("[Backend] Capture already running, client will detect via packet_batch")
                    # Don't send any event - client will auto-detect from packet_batch
                else:
                    print(f"[Backend] Interface configured: {interface}, emitting interface_ready")
                    socketio.emit('interface_ready', {'interface': interface})
            else:
                print("[Backend] No interface configured")
