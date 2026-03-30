#!/usr/bin/env bash
#
# Starts the OPNsense MCP bridge (expects `npm run start` in this repo from a bridge package).
#
# Config resolution (first match wins):
#   1. BRIDGE_CONFIG — path to a JSON file (absolute, or relative to this repo root)
#   2. bridge_config_opnsense.local.json in the repo root (gitignored; you create this file)
#
# First-time setup:
#   cp examples/bridge_config_opnsense.example.json bridge_config_opnsense.local.json
#   Replace every /absolute/path/to/opnsense-mcp with the path to this clone.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOCAL_CFG="$SCRIPT_DIR/bridge_config_opnsense.local.json"

if [ -n "${BRIDGE_CONFIG:-}" ]; then
  case "${BRIDGE_CONFIG}" in
    /*)
      CFG="${BRIDGE_CONFIG}"
      ;;
    *)
      CFG="$SCRIPT_DIR/${BRIDGE_CONFIG}"
      ;;
  esac
elif [ -f "$LOCAL_CFG" ]; then
  CFG="$LOCAL_CFG"
else
  echo "error: No bridge config found." >&2
  echo "" >&2
  echo "  cp \"$SCRIPT_DIR/examples/bridge_config_opnsense.example.json\" \"$LOCAL_CFG\"" >&2
  echo "  # Edit $LOCAL_CFG: replace /absolute/path/to/opnsense-mcp with $SCRIPT_DIR" >&2
  echo "" >&2
  echo "Or set BRIDGE_CONFIG to your JSON file (absolute path or path relative to repo root)." >&2
  exit 1
fi

if [ ! -f "$CFG" ]; then
  echo "error: BRIDGE_CONFIG file not found: $CFG" >&2
  exit 1
fi

export BRIDGE_CONFIG="$CFG"

echo "Starting OPNsense MCP Bridge..." >&2
echo "Using configuration: $BRIDGE_CONFIG" >&2
echo "" >&2

npm run start
