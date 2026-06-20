#!/usr/bin/env bash
# Roll out a pinned image tag on the deploy host (called from GitLab CI).
set -euo pipefail

IMAGE_REPO="${OPNSENSE_MCP_IMAGE_REPO:-hub.freeblizz.com/opnsense-mcp}"
IMAGE_TAG="${OPNSENSE_MCP_IMAGE_TAG:-${CI_COMMIT_SHORT_SHA:-}}"
QUADLET_APP="/etc/containers/systemd/opnsense-mcp-app.container"
INSTALL_ROOT="${OPNSENSE_MCP_INSTALL_ROOT:-/opt/containerdata/opnsense-mcp}"

if [[ -z "${IMAGE_TAG}" ]]; then
  echo "error: OPNSENSE_MCP_IMAGE_TAG or CI_COMMIT_SHORT_SHA is required" >&2
  exit 1
fi

if [[ "${IMAGE_TAG}" == "latest" ]]; then
  echo "error: deploy tag must be pinned (not latest)" >&2
  exit 1
fi

if [[ ! -f "${QUADLET_APP}" ]]; then
  echo "error: ${QUADLET_APP} not found — run install.sh on the host first" >&2
  exit 1
fi

sed -i "s|^Image=.*|Image=${IMAGE_REPO}:${IMAGE_TAG}|" "${QUADLET_APP}"
sed -i "s|hub.freeblizz.com/opnsense-mcp:.*|${IMAGE_REPO}:${IMAGE_TAG}|" "${QUADLET_APP}"
sed -i "s|localhost/opnsense-mcp:.*|${IMAGE_REPO}:${IMAGE_TAG}|" "${QUADLET_APP}"

if [[ -f "${INSTALL_ROOT}/environment" ]]; then
  grep -v '^OPNSENSE_MCP_IMAGE_TAG=' "${INSTALL_ROOT}/environment" >"${INSTALL_ROOT}/environment.tmp" || true
  printf 'OPNSENSE_MCP_IMAGE_TAG=%s\n' "${IMAGE_TAG}" >>"${INSTALL_ROOT}/environment.tmp"
  mv "${INSTALL_ROOT}/environment.tmp" "${INSTALL_ROOT}/environment"
  chmod 600 "${INSTALL_ROOT}/environment"
fi

podman pull "${IMAGE_REPO}:${IMAGE_TAG}"
podman rm -f opnsense-mcp-app opnsense-mcp-caddy 2>/dev/null || true
systemctl daemon-reload
systemctl restart opnsense-mcp-app.service opnsense-mcp-caddy.service || systemctl restart opnsense-mcp-app.service

podman ps --filter name=opnsense-mcp-app --format '{{.Image}}'
