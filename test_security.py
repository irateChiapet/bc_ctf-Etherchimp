#!/usr/bin/env python3
"""
Security test suite for --no-upload download functionality.
Tests for LFI, path traversal, and other web-based vulnerabilities.
"""

import os
import sys
from werkzeug.utils import secure_filename

# Test cases for path traversal and LFI attacks
TEST_CASES = [
    # Path traversal attempts
    ("../../../etc/passwd", "Path traversal with ../"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "URL-encoded path traversal"),
    ("..\\..\\..\\windows\\system32\\config\\sam", "Windows path traversal"),
    ("./../../../etc/passwd", "Mixed path traversal"),
    ("....//....//....//etc/passwd", "Double slash traversal"),

    # Absolute path attempts
    ("/etc/passwd", "Absolute Linux path"),
    ("/etc/shadow", "Absolute Linux path to shadow"),
    ("C:\\Windows\\System32\\config\\sam", "Absolute Windows path"),

    # Null byte injection (historical vulnerability)
    ("test.pcap%00.txt", "Null byte injection (URL encoded)"),
    ("test.pcap\x00.txt", "Null byte injection (raw)"),

    # Directory traversal
    (".", "Current directory access"),
    ("..", "Parent directory access"),
    ("./", "Current directory with slash"),
    ("../", "Parent directory with slash"),

    # Non-PCAP file attempts
    ("test.txt", "Plain text file"),
    ("test.sh", "Shell script"),
    ("test.py", "Python script"),
    (".env", "Environment file"),
    ("config.yaml", "Config file"),

    # Mixed attacks
    ("../uploads/test.txt", "Traversal then valid dir with invalid extension"),
    ("uploads/../../../etc/passwd.pcap", "Valid dir then traversal with fake extension"),

    # Symlink attack simulation (filename only)
    ("symlink_to_etc_passwd.pcap", "Symlink-like filename"),

    # Special characters
    ("test;ls.pcap", "Command injection attempt in filename"),
    ("test&whoami.pcap", "Command injection with ampersand"),
    ("test|cat /etc/passwd.pcap", "Pipe injection attempt"),
    ("test`id`.pcap", "Backtick command substitution"),
    ("test$(whoami).pcap", "Command substitution"),
]

def test_secure_filename():
    """Test werkzeug's secure_filename function."""
    print("=" * 80)
    print("Testing secure_filename() function")
    print("=" * 80)

    passed = 0
    failed = 0

    for test_input, description in TEST_CASES:
        safe = secure_filename(test_input)

        # Check if secure_filename properly sanitized the input
        is_safe = (
            safe == test_input and  # Not modified
            '..' not in safe and     # No parent directory
            '/' not in safe and      # No path separators
            '\\' not in safe and     # No Windows path separators
            safe != '' and           # Not empty
            (safe.endswith('.pcap') or safe.endswith('.pcapng'))  # Valid extension
        )

        status = "PASS" if not is_safe else "FAIL"

        if not is_safe:
            passed += 1
            print(f"✓ {status}: {description}")
            print(f"  Input:  '{test_input}'")
            print(f"  Output: '{safe}'")
        else:
            failed += 1
            print(f"✗ {status}: {description}")
            print(f"  Input:  '{test_input}'")
            print(f"  Output: '{safe}' (DANGEROUS: Looks valid!)")
        print()

    print("=" * 80)
    print(f"secure_filename() Results: {passed} passed, {failed} failed")
    print("=" * 80)
    print()

def test_path_validation():
    """Test path validation logic used in download endpoint."""
    print("=" * 80)
    print("Testing Path Validation Logic")
    print("=" * 80)

    upload_folder = os.path.abspath('/opt/bc_ctf-Etherchimp/uploads')

    test_filenames = [
        "test.pcap",
        "../etc/passwd",
        "../../etc/shadow",
        "/etc/passwd",
        "normal_file.pcap",
    ]

    for filename in test_filenames:
        safe_filename = secure_filename(filename)
        requested_path = os.path.abspath(os.path.join(upload_folder, safe_filename))

        # Check if path is within upload folder
        is_within = requested_path.startswith(upload_folder + os.sep)

        # Check if filename was modified
        is_modified = (safe_filename != filename)

        # Check if extension is valid
        is_valid_ext = safe_filename.endswith('.pcap') or safe_filename.endswith('.pcapng')

        is_safe = is_within and is_valid_ext and not is_modified

        status = "SAFE" if is_safe else "BLOCKED"
        print(f"{status}: '{filename}'")
        print(f"  Sanitized: '{safe_filename}'")
        print(f"  Path: '{requested_path}'")
        print(f"  Within upload folder: {is_within}")
        print(f"  Filename modified: {is_modified}")
        print(f"  Valid extension: {is_valid_ext}")
        print()

def test_endpoint_security():
    """Test the actual endpoint security checks."""
    print("=" * 80)
    print("Endpoint Security Check Simulation")
    print("=" * 80)

    upload_folder = os.path.abspath('/opt/bc_ctf-Etherchimp/uploads')

    def simulate_download_check(filename):
        """Simulate the security checks in download_pcap endpoint."""
        # Security check 1: Use secure_filename
        safe_filename = secure_filename(filename)

        # Security check 2: Verify filename hasn't been modified
        if safe_filename != filename:
            return False, "Path traversal detected"

        # Security check 3: Only allow .pcap and .pcapng files
        if not (safe_filename.endswith('.pcap') or safe_filename.endswith('.pcapng')):
            return False, "Invalid file extension"

        # Security check 4: Construct full path and verify it's within upload folder
        requested_path = os.path.abspath(os.path.join(upload_folder, safe_filename))

        # Security check 5: Verify the resolved path is still within upload folder
        if not requested_path.startswith(upload_folder + os.sep):
            return False, "Access denied - path outside upload folder"

        return True, "Access granted"

    attack_attempts = [
        "../../../etc/passwd",
        "../../etc/shadow",
        "/etc/passwd",
        "test.txt",
        "normal.pcap",
        "../uploads/file.pcap",
        "file;ls.pcap",
    ]

    blocked = 0
    allowed = 0

    for attempt in attack_attempts:
        is_allowed, reason = simulate_download_check(attempt)

        if is_allowed:
            allowed += 1
            print(f"✓ ALLOWED: '{attempt}' - {reason}")
        else:
            blocked += 1
            print(f"✗ BLOCKED: '{attempt}' - {reason}")

    print()
    print("=" * 80)
    print(f"Endpoint Security Results: {blocked} blocked, {allowed} allowed")
    print("=" * 80)

if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("PCAP Download Security Test Suite")
    print("Testing --no-upload functionality against LFI and path traversal attacks")
    print("=" * 80 + "\n")

    test_secure_filename()
    test_path_validation()
    test_endpoint_security()

    print("\n" + "=" * 80)
    print("Security Test Suite Complete")
    print("=" * 80)
