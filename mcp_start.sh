#!/bin/bash

# OPNsense MCP Server Start Script
# This script starts the OPNsense MCP server with proper environment setup
# All output must be JSON for MCP protocol compliance

set -e

# Redirect informational messages to stderr, keep stdout for JSON responses
# exec 1>&2  # REMOVED - this was breaking MCP protocol

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load credentials: ~/.env first, then optional second home dotenv for missing OPNSENSE_* only
# 1) Load from ~/.env first (documented path)
if [ -f ~/.env ]; then
    echo "Loading environment from ~/.env" >&2
    set -a
    # shellcheck disable=SC1090
    source ~/.env
    set +a
fi

# 2) Map common OPNSENSE_* aliases from ~/.env (if present)
#    (Your mcp server expects OPNSENSE_API_KEY / OPNSENSE_API_SECRET / OPNSENSE_FIREWALL_HOST.)
if [ -z "${OPNSENSE_API_KEY:-}" ] && [ -n "${OPNSENSE_KEY:-}" ]; then
    export OPNSENSE_API_KEY="${OPNSENSE_KEY}"
fi
if [ -z "${OPNSENSE_API_SECRET:-}" ] && [ -n "${OPNSENSE_SECRET:-}" ]; then
    export OPNSENSE_API_SECRET="${OPNSENSE_SECRET}"
fi
if [ -z "${OPNSENSE_FIREWALL_HOST:-}" ] && [ -n "${OPNSENSE_URL:-}" ]; then
    # Extract host from URLs like https://host.domain/path
    host="${OPNSENSE_URL#http://}"
    host="${host#https://}"
    host="${host%%/*}"
    if [ -n "$host" ]; then
        export OPNSENSE_FIREWALL_HOST="$host"
    fi
fi

# 3) Optional second home dotenv (missing OPNSENSE_* only)
if [ -f ~/.opnsense-env ]; then
    echo "Loading supplemental environment (missing OPNSENSE_* only)" >&2
    while IFS= read -r line || [ -n "$line" ]; do
        s="${line#"${line%%[![:space:]]*}"}" # trim leading whitespace
        if [ -z "$s" ] || [ "${s:0:1}" = "#" ]; then
            continue
        fi
        if [[ "$s" == export\ * ]]; then
            s="${s#export }"
        fi
        if [[ "$s" != *"="* ]]; then
            continue
        fi
        key="${s%%=*}"
        val="${s#*=}"

        # Remove surrounding quotes
        if [[ "$val" =~ ^\".*\"$ ]] || [[ "$val" =~ ^\'.*\'$ ]]; then
            val="${val:1:${#val}-2}"
        fi

        if [ -z "${!key:-}" ]; then
            export "$key=$val"
        fi
    done < ~/.opnsense-env
fi

# Set default environment variables
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
export DEBUG=${DEBUG:-1}

# Check if virtual environment exists and activate it
if [ -d ".venv" ]; then
    echo "Activating virtual environment (.venv)" >&2
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "Activating virtual environment (venv)" >&2
    source venv/bin/activate
else
    echo "Warning: No virtual environment found (.venv or venv)" >&2
fi

# Hosted MCP runtimes (e.g. Glama) may create .venv without installing project
# dependencies. Do not require requirements.txt — some images omit it and only
# ship opnsense_mcp/ + pyproject.toml.
if [ -n "${VIRTUAL_ENV:-}" ]; then
    PY="$VIRTUAL_ENV/bin/python3"
    if ! "$PY" -c "import pydantic" 2>/dev/null; then
        echo "Python deps missing in venv; installing..." >&2
        if ! "$PY" -m pip --version >/dev/null 2>&1; then
            echo "pip missing from venv; running ensurepip..." >&2
            "$PY" -m ensurepip --upgrade --default-pip
        fi
        export PIP_DISABLE_PIP_VERSION_CHECK=1
        if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
            "$PY" -m pip install --no-cache-dir -r "$SCRIPT_DIR/requirements.txt"
        elif [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
            echo "requirements.txt not in image; pip install from pyproject.toml..." >&2
            "$PY" -m pip install --no-cache-dir "$SCRIPT_DIR"
        else
            echo "No requirements.txt or pyproject.toml; installing minimal runtime pins..." >&2
            "$PY" -m pip install --no-cache-dir \
                "pydantic>=2.0.0" \
                "requests>=2.31.0" \
                "httpx>=0.24.0" \
                "python-dotenv>=1.0.0" \
                "fastmcp>=0.1.0" \
                "pyyaml>=6.0.0" \
                "fastapi>=0.100.0" \
                "uvicorn>=0.24.0" \
                "ruamel.yaml>=0.17.0" \
                "python-multipart>=0.0.6" \
                "typing-extensions>=4.0.0" \
                "passlib[bcrypt]>=1.7.4" \
                "paramiko>=3.0.0"
        fi
    fi
fi

# Check if required environment variables are set
if [ -z "$OPNSENSE_FIREWALL_HOST" ]; then
    echo "Warning: OPNSENSE_FIREWALL_HOST not set in environment" >&2
fi

if [ -z "$OPNSENSE_API_KEY" ]; then
    echo "Warning: OPNSENSE_API_KEY not set in environment" >&2
fi

if [ -z "$OPNSENSE_API_SECRET" ]; then
    echo "Warning: OPNSENSE_API_SECRET not set in environment" >&2
fi

# Start the MCP server
echo "Starting OPNsense MCP Server..." >&2

# Use the virtual environment's Python if available
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Using virtual environment Python: $VIRTUAL_ENV/bin/python3" >&2
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    exec "$VIRTUAL_ENV/bin/python3" opnsense_mcp/server.py
else
    echo "Using system Python" >&2
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    exec python3 opnsense_mcp/server.py
fi
