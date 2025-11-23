#!/bin/bash
# Wrapper script to run Etherchimp standalone binary
# Handles the /tmp noexec issue by using /root/tmp

# Ensure /root/tmp exists
mkdir -p /root/tmp

# Export TMPDIR for PyInstaller extraction
export TMPDIR=/root/tmp

# Run the binary with all arguments passed through
exec ./dist/etherchimp "$@"
