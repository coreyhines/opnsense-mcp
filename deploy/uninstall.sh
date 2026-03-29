#!/usr/bin/env bash
# Remove quadlet units / optionally Docker Compose stack. Run as root.
# Does not delete install-root env file or TLS certs unless --purge-env.
#
set -euo pipefail

readonly INSTALL_ROOT="${OPNSENSE_MCP_INSTALL_ROOT:-/opt/containerdata/opnsense-mcp}"
readonly SRC_DIR="${INSTALL_ROOT}/src"
readonly POD_NAME="${OPNSENSE_MCP_POD_NAME:-opnsense-mcp-pod}"
readonly QUADLET_DIR=/etc/containers/systemd
readonly LEGACY_QUADLET_SUBDIR=/etc/containers/systemd/opnsense-mcp
PURGE_ENV=0
RUNTIME="${OPNSENSE_MCP_RUNTIME:-podman}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-env) PURGE_ENV=1; shift ;;
    --runtime)
      RUNTIME="${2:-}"
      shift 2
      ;;
    -h | --help)
      echo "Usage: $0 [--runtime podman|docker] [--purge-env]" >&2
      echo "  Podman: removes opnsense-mcp.pod, opnsense-mcp-app.container, opnsense-mcp-caddy.container + legacy names." >&2
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if [[ "$RUNTIME" == "podman" ]]; then
  systemctl disable --now opnsense-mcp-caddy.service 2>/dev/null || true
  systemctl disable --now caddy-opnsense-mcp.service 2>/dev/null || true
  systemctl disable --now opnsense-mcp-app.service 2>/dev/null || true
  systemctl disable --now opnsense-mcp.service 2>/dev/null || true
  systemctl disable --now opnsense-mcp-pod.service 2>/dev/null || true
  systemctl disable --now "pod-${POD_NAME}.service" 2>/dev/null || true
  systemctl disable --now pod-opnsense-mcp.service 2>/dev/null || true
  systemctl disable --now opnsense-mcp-pod-pod.service 2>/dev/null || true
  for _qd in "${QUADLET_DIR}" "${LEGACY_QUADLET_SUBDIR}"; do
    rm -f "${_qd}/opnsense-mcp-caddy.container"
    rm -f "${_qd}/caddy-opnsense-mcp.container"
    rm -f "${_qd}/opnsense-mcp-app.container"
    rm -f "${_qd}/opnsense-mcp.container"
    rm -f "${_qd}/opnsense-mcp.pod"
    rm -f "${_qd}/opnsense-mcp-pod.pod"
    rm -f "${_qd}/${POD_NAME}.pod"
  done
  rmdir "${LEGACY_QUADLET_SUBDIR}" 2>/dev/null || true
  systemctl daemon-reload
  podman rmi localhost/opnsense-mcp:latest 2>/dev/null || true
elif [[ "$RUNTIME" == "docker" ]]; then
  if [[ -d "${SRC_DIR}/deploy" ]]; then
    (cd "${SRC_DIR}" && docker compose -p opnsense-mcp -f deploy/docker-compose.yml down --rmi local 2>/dev/null) || true
  fi
else
  echo "Invalid --runtime" >&2
  exit 1
fi

if [[ "${PURGE_ENV}" -eq 1 ]]; then
  rm -f "${INSTALL_ROOT}/environment"
  echo "Removed ${INSTALL_ROOT}/environment" >&2
fi

echo "Uninstall steps for ${RUNTIME} completed. See docs/CENTRALIZED_DEPLOY_SPEC.md (manual uninstall) for leftovers." >&2
