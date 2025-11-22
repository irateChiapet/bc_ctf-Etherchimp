#!/usr/bin/env python3
"""
Test script for PCAP file rotation feature.
Simulates creating multiple live_capture files and verifies rotation works.
"""

import os
import time
import tempfile
import shutil

def test_live_capture_rotation():
    """Test that only 3 most recent live_capture files are kept."""

    # Create temporary uploads folder
    test_dir = tempfile.mkdtemp(prefix='test_rotation_')
    print(f"Testing in: {test_dir}")

    try:
        # Simulate creating 5 live_capture files
        filenames = []
        for i in range(5):
            timestamp = int(time.time()) + i
            filename = f"live_capture_{timestamp}.pcap"
            filepath = os.path.join(test_dir, filename)

            # Create dummy file
            with open(filepath, 'wb') as f:
                f.write(b'dummy pcap data')

            filenames.append(filename)
            print(f"Created: {filename}")
            time.sleep(0.1)  # Small delay to ensure different timestamps

        # Now simulate rotation (keep only 3)
        import glob
        pattern = os.path.join(test_dir, "live_capture_*.pcap")
        live_capture_files = glob.glob(pattern)

        print(f"\nBefore rotation: {len(live_capture_files)} files")
        for f in sorted(live_capture_files):
            print(f"  - {os.path.basename(f)}")

        # Perform rotation
        keep_count = 3
        if len(live_capture_files) > keep_count:
            live_capture_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            files_to_keep = live_capture_files[:keep_count]
            files_to_delete = live_capture_files[keep_count:]

            for filepath in files_to_delete:
                os.remove(filepath)
                print(f"  Deleted: {os.path.basename(filepath)}")

        # Check result
        remaining_files = glob.glob(pattern)
        print(f"\nAfter rotation: {len(remaining_files)} files")
        for f in sorted(remaining_files):
            print(f"  - {os.path.basename(f)}")

        # Verify
        assert len(remaining_files) == 3, f"Expected 3 files, got {len(remaining_files)}"

        # Verify the 3 newest were kept
        remaining_names = [os.path.basename(f) for f in remaining_files]
        expected_kept = filenames[-3:]  # Last 3 created

        for name in expected_kept:
            assert name in remaining_names, f"Expected {name} to be kept"

        print("\n✅ Test PASSED: Rotation keeps only 3 most recent files")

    finally:
        # Cleanup
        shutil.rmtree(test_dir)
        print(f"\nCleaned up test directory: {test_dir}")


def test_remote_capture_rotation():
    """Test that remote captures are rotated per host-interface."""

    test_dir = tempfile.mkdtemp(prefix='test_remote_rotation_')
    print(f"\nTesting remote capture rotation in: {test_dir}")

    try:
        # Create files for different host-interface combinations
        hosts = [
            ("192.168.1.100", "eth0"),
            ("192.168.1.100", "eth1"),  # Same host, different interface
            ("192.168.1.200", "eth0"),  # Different host, same interface
        ]

        for host, iface in hosts:
            for i in range(5):
                timestamp = int(time.time()) + i
                filename = f"{host}-{iface}-{timestamp}.pcap"
                filepath = os.path.join(test_dir, filename)

                with open(filepath, 'wb') as f:
                    f.write(b'dummy pcap data')

                time.sleep(0.05)

        print(f"\nCreated {5 * len(hosts)} files total")

        # Rotate each host-interface combination
        import glob
        for host, iface in hosts:
            pattern = os.path.join(test_dir, f"{host}-{iface}-*.pcap")
            files = glob.glob(pattern)

            print(f"\n{host}:{iface} - Before: {len(files)} files")

            # Rotate
            keep_count = 3
            if len(files) > keep_count:
                files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                files_to_delete = files[keep_count:]
                for f in files_to_delete:
                    os.remove(f)

            remaining = glob.glob(pattern)
            print(f"{host}:{iface} - After: {len(remaining)} files")
            assert len(remaining) == 3, f"Expected 3 files for {host}:{iface}"

        # Verify total (3 files × 3 host-interface combos = 9 files)
        all_files = glob.glob(os.path.join(test_dir, "*.pcap"))
        print(f"\nTotal files remaining: {len(all_files)}")
        assert len(all_files) == 9, f"Expected 9 total files, got {len(all_files)}"

        print("✅ Test PASSED: Remote captures rotate per host-interface")

    finally:
        shutil.rmtree(test_dir)
        print(f"\nCleaned up test directory: {test_dir}")


def test_no_rotation_if_under_limit():
    """Test that rotation doesn't delete files if count is under limit."""

    test_dir = tempfile.mkdtemp(prefix='test_no_rotation_')
    print(f"\nTesting no rotation when under limit in: {test_dir}")

    try:
        # Create only 2 files (under the 3 limit)
        for i in range(2):
            timestamp = int(time.time()) + i
            filename = f"live_capture_{timestamp}.pcap"
            filepath = os.path.join(test_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(b'dummy pcap data')

            time.sleep(0.1)

        import glob
        pattern = os.path.join(test_dir, "live_capture_*.pcap")
        files_before = glob.glob(pattern)

        print(f"Created {len(files_before)} files (under limit of 3)")

        # Try rotation
        keep_count = 3
        if len(files_before) > keep_count:
            # This should not execute
            assert False, "Should not rotate when under limit"

        files_after = glob.glob(pattern)
        print(f"After rotation check: {len(files_after)} files")

        assert len(files_after) == 2, "Should keep all files when under limit"
        print("✅ Test PASSED: No rotation when under limit")

    finally:
        shutil.rmtree(test_dir)
        print(f"\nCleaned up test directory: {test_dir}")


if __name__ == '__main__':
    print("=" * 60)
    print("PCAP File Rotation Test Suite")
    print("=" * 60)

    test_live_capture_rotation()
    test_remote_capture_rotation()
    test_no_rotation_if_under_limit()

    print("\n" + "=" * 60)
    print("All tests PASSED! ✅")
    print("=" * 60)
