#!/usr/bin/env bash
# Roll out a pinned image tag on the deploy host (called from Forgejo Actions).
set -euo pipefail

IMAGE_REPO="${OPNSENSE_MCP_IMAGE_REPO:-}"
IMAGE_TAG="${OPNSENSE_MCP_IMAGE_TAG:-${CI_COMMIT_SHORT_SHA:-}}"
QUADLET_DIR="${OPNSENSE_MCP_QUADLET_DIR:-/etc/containers/systemd/opnsense-mcp}"
QUADLET_APP="${QUADLET_DIR}/opnsense-mcp-app.container"
# A host installed before the per-service directory layout still has the file
# flat in the parent. Patch whichever one is actually there, and say which.
if [[ ! -f "${QUADLET_APP}" && -f "/etc/containers/systemd/opnsense-mcp-app.container" ]]; then
  QUADLET_APP="/etc/containers/systemd/opnsense-mcp-app.container"
  echo "note: patching legacy flat quadlet ${QUADLET_APP}; run install.sh to migrate" >&2
fi
INSTALL_ROOT="${OPNSENSE_MCP_INSTALL_ROOT:-/opt/containerdata/opnsense-mcp}"

if [[ -z "${IMAGE_REPO}" ]]; then
  echo "error: OPNSENSE_MCP_IMAGE_REPO is required (set the registry in CI)" >&2
  exit 1
fi

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

# -i.bak, not bare -i: the latter is GNU-only, and the tests run this script.
sed -i.bak \
  -e "s|^Image=.*|Image=${IMAGE_REPO}:${IMAGE_TAG}|" \
  -e "s|^Image=.*/opnsense-mcp:.*|Image=${IMAGE_REPO}:${IMAGE_TAG}|" \
  -e "s|localhost/opnsense-mcp:.*|${IMAGE_REPO}:${IMAGE_TAG}|" \
  "${QUADLET_APP}"
rm -f "${QUADLET_APP}.bak"

if [[ -f "${INSTALL_ROOT}/environment" ]]; then
  grep -v '^OPNSENSE_MCP_IMAGE_TAG=' "${INSTALL_ROOT}/environment" >"${INSTALL_ROOT}/environment.tmp" || true
  printf 'OPNSENSE_MCP_IMAGE_TAG=%s\n' "${IMAGE_TAG}" >>"${INSTALL_ROOT}/environment.tmp"
  mv "${INSTALL_ROOT}/environment.tmp" "${INSTALL_ROOT}/environment"
  chmod 600 "${INSTALL_ROOT}/environment"
fi

# Container names come from the quadlets, which install.sh lets vary
# (OPNSENSE_MCP_CONTAINER_NAME); hard-coding them made `podman rm` a no-op.
container_name() {
  local file=$1 fallback=$2 name
  name="$(sed -n 's/^ContainerName=//p' "${file}" | head -n 1)"
  printf '%s' "${name:-${fallback}}"
}

WANT="${IMAGE_REPO}:${IMAGE_TAG}"
APP_CONTAINER="$(container_name "${QUADLET_APP}" opnsense-mcp-app)"
UNITS=(opnsense-mcp-app.service)
CONTAINERS=("${APP_CONTAINER}")
CADDY_QUADLET="$(dirname "${QUADLET_APP}")/opnsense-mcp-caddy.container"
if [[ -f "${CADDY_QUADLET}" ]]; then
  UNITS+=(opnsense-mcp-caddy.service)
  CONTAINERS+=("$(container_name "${CADDY_QUADLET}" opnsense-mcp-caddy)")
fi

podman pull "${WANT}"
podman rm -f "${CONTAINERS[@]}" 2>/dev/null || true
systemctl daemon-reload
# No `|| restart app` fallback: it hid a failed Caddy restart and exited 0.
systemctl restart "${UNITS[@]}"

# Verify the rollout rather than printing whatever is running: the old
# final `podman ps` exited 0 for the new tag, the old tag, or nothing.
for unit in "${UNITS[@]}"; do
  if ! systemctl is-active --quiet "${unit}"; then
    echo "error: ${unit} is not active after the restart" >&2
    exit 1
  fi
done
running="$(podman inspect --format '{{.ImageName}}' "${APP_CONTAINER}" 2>/dev/null || true)"
if [[ "${running}" != "${WANT}" ]]; then
  echo "error: ${APP_CONTAINER} runs '${running:-nothing}', not ${WANT}" >&2
  exit 1
fi
echo "deployed ${running} (${UNITS[*]} active)"
