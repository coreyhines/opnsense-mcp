#!/bin/bash

# OPNsense MCP Server Start Script
# This script starts the OPNsense MCP server with proper environment setup

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment variables if .opnsense-env exists
if [ -f ~/.opnsense-env ]; then
    echo "Loading environment from ~/.opnsense-env"
    export $(grep -v '^#' ~/.opnsense-env | xargs)
fi

# Set default environment variables
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
export DEBUG=${DEBUG:-1}

# Check if virtual environment exists and activate it
if [ -d ".venv" ]; then
    echo "Activating virtual environment (.venv)"
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "Activating virtual environment (venv)"
    source venv/bin/activate
else
    echo "Warning: No virtual environment found (.venv or venv)"
fi

# Check if required environment variables are set
if [ -z "$OPNSENSE_FIREWALL_HOST" ]; then
    echo "Warning: OPNSENSE_FIREWALL_HOST not set in environment"
fi

if [ -z "$OPNSENSE_API_KEY" ]; then
    echo "Warning: OPNSENSE_API_KEY not set in environment"
fi

if [ -z "$OPNSENSE_API_SECRET" ]; then
    echo "Warning: OPNSENSE_API_SECRET not set in environment"
fi

# Start the MCP server
echo "Starting OPNsense MCP Server..."

# Use the virtual environment's Python if available
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Using virtual environment Python: $VIRTUAL_ENV/bin/python3"
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    exec "$VIRTUAL_ENV/bin/python3" opnsense_mcp/server.py
else
    echo "Using system Python"
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    exec python3 opnsense_mcp/server.py
fi 
