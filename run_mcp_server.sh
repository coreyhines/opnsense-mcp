#!/bin/bash

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Set environment variables
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
export MCP_TRANSPORT=stdio
export PYTHONPATH=.
export DEBUG=true
export LOG_LEVEL=DEBUG

# Run the server with proper Python path
python3.12 -m opnsense_mcp.server 
