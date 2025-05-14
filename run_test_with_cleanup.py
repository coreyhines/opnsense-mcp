#!/usr/bin/env python3
"""
Run tests with auto cleanup.
This script runs the specified test and then cleans up any artifacts.
"""

import os
import sys
import subprocess  # nosec
import argparse


def get_script_dir():
    """Get the directory of this script"""
    return os.path.dirname(os.path.abspath(__file__))


def run_test(test_script, args):
    """Run the specified test with arguments"""
    script_path = os.path.join(get_script_dir(), test_script)

    # Construct the command
    cmd = [sys.executable, script_path]
    if args:
        cmd.extend(args)

    print(f"Running test: {' '.join(cmd)}")

    # Run the test
    try:
        # NOTE: subprocess.run is used with shell=False and controlled input, which is safe. Bandit: # nosec
        subprocess.run(cmd, check=True)  # nosec
        return True
    except subprocess.CalledProcessError as e:
        print(f"Test failed with exit code {e.returncode}")
        return False


def run_cleanup():
    """Run the cleanup script"""
    cleanup_path = os.path.join(get_script_dir(), "cleanup.py")

    print("\nCleaning up test artifacts...")

    try:
        # NOTE: subprocess.run is used with shell=False and controlled input, which is safe. Bandit: # nosec
        subprocess.run([sys.executable, cleanup_path], check=True)  # nosec
        return True
    except subprocess.CalledProcessError as e:
        print(f"Cleanup failed with exit code {e.returncode}")
        return False


def main():
    """Parse arguments and run tests with cleanup"""
    parser = argparse.ArgumentParser(description="Run tests with auto cleanup")
    parser.add_argument("test_script", help="Test script to run (e.g., test_api.py)")
    parser.add_argument("args", nargs="*", help="Arguments to pass to the test script")

    args = parser.parse_args()

    # Run the test
    test_success = run_test(args.test_script, args.args)

    # Always run cleanup, regardless of test success
    cleanup_success = run_cleanup()

    # Exit with appropriate status
    if not test_success:
        sys.exit(1)
    if not cleanup_success:
        sys.exit(2)


if __name__ == "__main__":
    main()
