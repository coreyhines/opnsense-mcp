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

# The host's public key, pinned out of band: one or more known_hosts lines
# (e.g. `ssh-keyscan <host>` run from a trusted network and checked). This
# replaced trust-on-first-use, where ssh-keyscan's answer was appended with
# failures hidden and then ignored anyway under StrictHostKeyChecking=no.
if [[ -z "${OPNSENSE_MCP_DEPLOY_HOST_KEY:-}" ]]; then
  echo "error: OPNSENSE_MCP_DEPLOY_HOST_KEY is required (known_hosts line(s) for ${OPNSENSE_MCP_DEPLOY_HOST})" >&2
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
printf '%s\n' "${OPNSENSE_MCP_DEPLOY_HOST_KEY}" >~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
if ! ssh-keygen -F "${OPNSENSE_MCP_DEPLOY_HOST}" -f ~/.ssh/known_hosts >/dev/null 2>&1; then
  echo "error: OPNSENSE_MCP_DEPLOY_HOST_KEY has no entry for ${OPNSENSE_MCP_DEPLOY_HOST}" >&2
  exit 1
fi
# Every ssh/scp in the job refuses a host whose key does not match.
cat >~/.ssh/config <<'SSHCONFIG'
Host *
  StrictHostKeyChecking yes
  UserKnownHostsFile ~/.ssh/known_hosts
SSHCONFIG
chmod 600 ~/.ssh/config
