#!/usr/bin/env bash
# Configure SSH for opnsense-mcp deploy jobs.
set -euo pipefail

if [[ -z "${OPNSENSE_MCP_DEPLOY_SSH_KEY_B64:-}" && -z "${OPNSENSE_MCP_DEPLOY_SSH_KEY:-}" ]]; then
  echo "error: OPNSENSE_MCP_DEPLOY_SSH_KEY_B64 or OPNSENSE_MCP_DEPLOY_SSH_KEY is required" >&2
  exit 1
fi

if [[ -z "${OPNSENSE_MCP_DEPLOY_HOST:-}" ]]; then
  echo "error: OPNSENSE_MCP_DEPLOY_HOST is not set" >&2
  exit 1
fi

install -d -m 700 ~/.ssh
if [[ -n "${OPNSENSE_MCP_DEPLOY_SSH_KEY_B64:-}" ]]; then
  printf '%s' "${OPNSENSE_MCP_DEPLOY_SSH_KEY_B64}" | base64 -d >~/.ssh/id_ed25519
elif [[ -f "${OPNSENSE_MCP_DEPLOY_SSH_KEY}" ]]; then
  install -m 600 "${OPNSENSE_MCP_DEPLOY_SSH_KEY}" ~/.ssh/id_ed25519
else
  printf '%s\n' "${OPNSENSE_MCP_DEPLOY_SSH_KEY}" >~/.ssh/id_ed25519
fi
chmod 600 ~/.ssh/id_ed25519
if ! ssh-keygen -y -f ~/.ssh/id_ed25519 >/dev/null 2>&1; then
  echo "error: deploy SSH private key is invalid after setup" >&2
  exit 1
fi
ssh-keyscan -H "${OPNSENSE_MCP_DEPLOY_HOST}" >>~/.ssh/known_hosts 2>/dev/null || true
