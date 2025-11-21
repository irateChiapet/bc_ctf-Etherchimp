"""Log cleanup service for automatic retention management."""

import os
import time
import signal
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class LogCleanupService:
    """Service to automatically clean up old PCAP files and reload the system."""

    def __init__(self, upload_folder, retention_minutes=7, check_interval=60):
        """
        Initialize the log cleanup service.

        Args:
            upload_folder: Directory containing PCAP files to clean
            retention_minutes: Number of minutes to retain logs (default: 7)
            check_interval: How often to check for old files in seconds (default: 60)
        """
        self.upload_folder = upload_folder
        self.retention_seconds = retention_minutes * 60
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        logger.info(f"LogCleanupService initialized: retention={retention_minutes}min, check_interval={check_interval}s")

    def start(self):
        """Start the cleanup service in a background thread."""
        if self.running:
            logger.warning("Cleanup service already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.thread.start()
        logger.info("Log cleanup service started")

    def stop(self):
        """Stop the cleanup service."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Log cleanup service stopped")

    def _cleanup_loop(self):
        """Main cleanup loop running in background thread."""
        while self.running:
            try:
                deleted_count = self._cleanup_old_files()

                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old PCAP files")
                    # Trigger system reload (HUP) after cleanup
                    self._reload_system()

            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

            # Sleep for check_interval seconds
            time.sleep(self.check_interval)

    def _cleanup_old_files(self):
        """
        Delete PCAP files older than retention period.

        Returns:
            Number of files deleted
        """
        if not os.path.exists(self.upload_folder):
            logger.warning(f"Upload folder does not exist: {self.upload_folder}")
            return 0

        current_time = time.time()
        deleted_count = 0

        # Iterate through all PCAP files in the upload folder
        for filename in os.listdir(self.upload_folder):
            # Only process PCAP files (skip autoload.pcap as it's a template)
            if not (filename.endswith('.pcap') or filename.endswith('.pcapng')):
                continue

            # Skip autoload.pcap as it's used for initial file loading
            if filename == 'autoload.pcap':
                continue

            filepath = os.path.join(self.upload_folder, filename)

            try:
                # Get file modification time
                file_mtime = os.path.getmtime(filepath)
                file_age = current_time - file_mtime

                # Delete if older than retention period
                if file_age > self.retention_seconds:
                    logger.info(f"Deleting old file: {filename} (age: {file_age/60:.1f} minutes)")
                    os.remove(filepath)
                    deleted_count += 1
                else:
                    logger.debug(f"Keeping file: {filename} (age: {file_age/60:.1f} minutes)")

            except Exception as e:
                logger.error(f"Error processing file {filename}: {e}")

        return deleted_count

    def _reload_system(self):
        """
        Send SIGHUP signal to current process to trigger a reload.
        This is a graceful reload that restarts the application.
        """
        try:
            pid = os.getpid()
            logger.info(f"Sending SIGHUP signal to process {pid} to reload system")
            os.kill(pid, signal.SIGHUP)
        except Exception as e:
            logger.error(f"Error sending SIGHUP signal: {e}")
