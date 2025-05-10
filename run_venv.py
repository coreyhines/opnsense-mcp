#!/usr/bin/env python3
"""
Launcher script for OPNsense MCP Server using the virtual environment
"""
import os
import sys
import subprocess

# Get the directory where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define paths
venv_dir = os.path.join(script_dir, "venv")
if sys.platform == "win32":
    python_cmd = os.path.join(venv_dir, "Scripts", "python")
else:
    python_cmd = os.path.join(venv_dir, "bin", "python")

# Define the command to run
launcher_script = os.path.join(script_dir, "universal_launcher.py")
command = [python_cmd, launcher_script]

# Run the command
print(f"Running: {' '.join(command)}")
try:
    subprocess.run(command, check=True)
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
    sys.exit(1)
