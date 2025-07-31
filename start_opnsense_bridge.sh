#!/bin/bash

# Start the OPNsense MCP Bridge
echo "Starting OPNsense MCP Bridge..."
echo "Using configuration: bridge_config_opnsense.json"
echo ""

# Set the configuration file
export BRIDGE_CONFIG=bridge_config_opnsense.json

# Start the bridge
npm run start
