#!/usr/bin/env bash
# OPNsense MCP centralized install (Linux amd64). GitLab is the default clone source.
# Idempotent: safe to re-run (git pull, rebuild, systemd reload).
#
#   curl -fsSL 'https://gitlab.freeblizz.com/coreyhines/opensense-mcp/-/raw/main/deploy/install.sh' | sudo bash
# Optional: clone a different ref (fork, release branch, etc.):
#   sudo env OPNSENSE_MCP_GIT_REF=my-branch bash deploy/install.sh
# Override clone URL:
#   sudo OPNSENSE_MCP_REPO_URL='https://gitlab.../opensense-mcp.git' bash deploy/install.sh
#
set -euo pipefail

readonly DEFAULT_REPO_URL="${OPNSENSE_MCP_REPO_URL:-https://gitlab.freeblizz.com/coreyhines/opensense-mcp.git}"
# Default git ref is main (see docs/CENTRALIZED_DEPLOY_SPEC.md); override with OPNSENSE_MCP_GIT_REF.
readonly GIT_REF="${OPNSENSE_MCP_GIT_REF:-main}"
# Default matches strongpod-style layout under /opt/containerdata (override with OPNSENSE_MCP_INSTALL_ROOT).
readonly INSTALL_ROOT="${OPNSENSE_MCP_INSTALL_ROOT:-/opt/containerdata/opnsense-mcp}"
readonly SRC_DIR="${INSTALL_ROOT}/src"
readonly CADDYFILE_HOST="${INSTALL_ROOT}/Caddyfile"
readonly IMAGE_REPO="${OPNSENSE_MCP_IMAGE_REPO:-localhost/opnsense-mcp}"
readonly IMAGE_TAG="${OPNSENSE_MCP_IMAGE_TAG:-latest}"
RUNTIME="${OPNSENSE_MCP_RUNTIME:-podman}"

usage() {
  echo "Usage: $0 [--runtime podman|docker]" >&2
  echo "  Env: OPNSENSE_MCP_REPO_URL, OPNSENSE_MCP_GIT_REF, OPNSENSE_MCP_INSTALL_ROOT," >&2
  echo "       OPNSENSE_MCP_IMAGE_REPO, OPNSENSE_MCP_IMAGE_TAG" >&2
  echo "  Quadlet (Podman): OPNSENSE_MCP_POD_NAME, OPNSENSE_MCP_CONTAINER_NAME," >&2
  echo "    OPNSENSE_MCP_CADDY_CONTAINER_NAME, OPNSENSE_MCP_NETWORK, OPNSENSE_MCP_IP," >&2
  echo "    OPNSENSE_MCP_IP6, OPNSENSE_MCP_DNS (space-separated), OPNSENSE_MCP_TLS_CERTS" >&2
  echo "  Interactive prompts run only when stdin is a TTY (not when using curl|bash)." >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      RUNTIME="${2:-}"
      if [[ -z "${RUNTIME}" ]]; then echo "--runtime needs a value" >&2; exit 1; fi
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "${RUNTIME}" != "podman" && "${RUNTIME}" != "docker" ]]; then
  echo "Invalid --runtime (use podman or docker)" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This installer must run as root (sudo)." >&2
  exit 1
fi

echo "opnsense-mcp install: INSTALL_ROOT=${INSTALL_ROOT} SRC_DIR=${SRC_DIR} GIT_REF=${GIT_REF} RUNTIME=${RUNTIME}" >&2

mkdir -p "${INSTALL_ROOT}" /etc/containers/systemd/opnsense-mcp

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${GIT_REF}" "${DEFAULT_REPO_URL}" "${SRC_DIR}"
else
  # Install-managed tree: always match remote (avoids diverged shallow clones breaking pull --ff-only).
  git -C "${SRC_DIR}" fetch origin "${GIT_REF}" --depth 1
  git -C "${SRC_DIR}" reset --hard "origin/${GIT_REF}"
fi

verify_deploy_tree() {
  local missing=0
  local f
  for f in \
    "${SRC_DIR}/deploy/environment.example" \
    "${SRC_DIR}/deploy/Containerfile" \
    "${SRC_DIR}/deploy/opnsense-mcp.pod.example" \
    "${SRC_DIR}/deploy/opnsense-mcp-app.container.example" \
    "${SRC_DIR}/deploy/opnsense-mcp-caddy.container.example"; do
    if [[ ! -f "${f}" ]]; then
      echo "Missing required file: ${f}" >&2
      missing=1
    fi
  done
  if [[ "${missing}" -ne 0 ]]; then
    echo "Clone at ${SRC_DIR} does not contain deploy/ (wrong branch?)." >&2
    echo "Re-run with: sudo env OPNSENSE_MCP_GIT_REF=main bash deploy/install.sh" >&2
    exit 1
  fi
}

verify_deploy_tree

# --- Quadlet: container names, optional Podman network/static IPs, TLS cert host path ---
collect_quadlet_settings() {
  local tty_device=/dev/tty
  local interactive=0
  if [[ -t 0 ]] && [[ -e "${tty_device}" ]] && [[ -r "${tty_device}" ]]; then
    interactive=1
  fi

  if [[ "${interactive}" -eq 1 ]]; then
    if [[ -z "${OPNSENSE_MCP_POD_NAME:-}" ]]; then
      read -r -p "Pod name (Podman PodName=; quadlet file stays opnsense-mcp.pod) [opnsense-mcp-pod]: " OPNSENSE_MCP_POD_NAME <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_CONTAINER_NAME:-}" ]]; then
      read -r -p "App container name (Podman ContainerName=) [opnsense-mcp-app]: " OPNSENSE_MCP_CONTAINER_NAME <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_CADDY_CONTAINER_NAME:-}" ]]; then
      read -r -p "Caddy container name [opnsense-mcp-caddy]: " OPNSENSE_MCP_CADDY_CONTAINER_NAME <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_NETWORK:-}" ]]; then
      read -r -p "Pod Network= (empty to omit; e.g. net-10): " OPNSENSE_MCP_NETWORK <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_IP:-}" ]]; then
      read -r -p "Pod static IP= (empty to omit): " OPNSENSE_MCP_IP <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_IP6:-}" ]]; then
      read -r -p "Pod static IP6= (empty to omit): " OPNSENSE_MCP_IP6 <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_DNS:-}" ]]; then
      read -r -p "Pod DNS= (space-separated, empty to omit; e.g. 10.0.2.2 10.0.10.4): " OPNSENSE_MCP_DNS <"${tty_device}" || true
    fi
    if [[ -z "${OPNSENSE_MCP_TLS_CERTS:-}" ]]; then
      read -r -p "Host path to TLS PEMs (Caddy + optional MCP mount) [/opt/certs/wild]: " OPNSENSE_MCP_TLS_CERTS <"${tty_device}" || true
    fi
  fi

  OPNSENSE_MCP_POD_NAME=${OPNSENSE_MCP_POD_NAME:-opnsense-mcp-pod}
  OPNSENSE_MCP_CONTAINER_NAME=${OPNSENSE_MCP_CONTAINER_NAME:-opnsense-mcp-app}
  OPNSENSE_MCP_CADDY_CONTAINER_NAME=${OPNSENSE_MCP_CADDY_CONTAINER_NAME:-opnsense-mcp-caddy}
  OPNSENSE_MCP_TLS_CERTS=${OPNSENSE_MCP_TLS_CERTS:-/opt/certs/wild}
  # set -u: optional quadlet keys must be bound even when not in the shell env or install file.
  OPNSENSE_MCP_NETWORK=${OPNSENSE_MCP_NETWORK:-}
  OPNSENSE_MCP_IP=${OPNSENSE_MCP_IP:-}
  OPNSENSE_MCP_IP6=${OPNSENSE_MCP_IP6:-}
  OPNSENSE_MCP_DNS=${OPNSENSE_MCP_DNS:-}
}

write_opnsense_mcp_pod() {
  local out=$1
  local pod_name=$2
  {
    printf '%s\n' '[Unit]'
    printf '%s\n' 'Description=OPNsense MCP pod (shared network for Caddy + MCP)'
    printf '%s\n' 'Wants=network-online.target'
    printf '%s\n' 'After=network-online.target'
    printf '%s\n' ''
    printf '%s\n' '[Pod]'
    printf '%s\n' "PodName=${pod_name}"
    [[ -n "${OPNSENSE_MCP_NETWORK:-}" ]] && printf '%s\n' "Network=${OPNSENSE_MCP_NETWORK}"
    [[ -n "${OPNSENSE_MCP_IP:-}" ]] && printf '%s\n' "IP=${OPNSENSE_MCP_IP}"
    [[ -n "${OPNSENSE_MCP_IP6:-}" ]] && printf '%s\n' "IP6=${OPNSENSE_MCP_IP6}"
    local dns
    for dns in ${OPNSENSE_MCP_DNS:-}; do
      [[ -n "${dns}" ]] && printf '%s\n' "DNS=${dns}"
    done
    printf '%s\n' ''
    printf '%s\n' '[Service]'
    printf '%s\n' 'Restart=on-failure'
    printf '%s\n' ''
    printf '%s\n' '[Install]'
    printf '%s\n' 'WantedBy=multi-user.target'
  } >"${out}"
  chmod 644 "${out}"
}

write_opnsense_mcp_quadlet() {
  local out=$1
  local pod_svc=$2
  local pod_quadlet_file=$3
  {
    printf '%s\n' '[Unit]'
    printf '%s\n' 'Description=OPNsense MCP (Podman quadlet, mcp-proxy SSE)'
    printf '%s\n' "After=network-online.target ${pod_svc}"
    printf '%s\n' 'Wants=network-online.target'
    printf '%s\n' "Requires=${pod_svc}"
    printf '%s\n' ''
    printf '%s\n' '[Container]'
    printf '%s\n' "Pod=${pod_quadlet_file}"
    printf '%s\n' "Image=${IMAGE_REPO}:${IMAGE_TAG}"
    printf '%s\n' "ContainerName=${OPNSENSE_MCP_CONTAINER_NAME}"
    printf '%s\n' "Environment=OPNSENSE_MCP_INSTALL_ROOT=${INSTALL_ROOT}"
    printf '%s\n' "EnvironmentFile=${INSTALL_ROOT}/environment"
    printf '%s\n' "Volume=${INSTALL_ROOT}:${INSTALL_ROOT}:ro,Z"
    printf '%s\n' "Volume=${OPNSENSE_MCP_TLS_CERTS}:/opt/certs/wild:ro,Z"
    printf '%s\n' ''
    printf '%s\n' '[Service]'
    printf '%s\n' 'Restart=on-failure'
    printf '%s\n' 'RestartSec=10'
    printf '%s\n' 'TimeoutStartSec=120'
    printf '%s\n' 'TimeoutStopSec=40'
    printf '%s\n' ''
    printf '%s\n' '[Install]'
    printf '%s\n' 'WantedBy=multi-user.target'
  } >"${out}"
  chmod 644 "${out}"
}

write_caddy_quadlet() {
  local out=$1
  local pod_svc=$2
  local app_service=$3
  local pod_quadlet_file=$4
  {
    printf '%s\n' '[Unit]'
    printf '%s\n' 'Description=TLS front for OPNsense MCP (Caddy)'
    printf '%s\n' 'Documentation=https://caddyserver.com/docs/caddyfile'
    printf '%s\n' "After=network-online.target ${pod_svc} ${app_service}"
    printf '%s\n' 'Wants=network-online.target'
    printf '%s\n' "Requires=${pod_svc}"
    printf '%s\n' "Requires=${app_service}"
    printf '%s\n' ''
    printf '%s\n' '[Container]'
    printf '%s\n' "Pod=${pod_quadlet_file}"
    printf '%s\n' 'Image=docker.io/library/caddy:2-alpine'
    printf '%s\n' "ContainerName=${OPNSENSE_MCP_CADDY_CONTAINER_NAME}"
    printf '%s\n' "Volume=${OPNSENSE_MCP_TLS_CERTS}:/opt/certs/wild:ro,Z"
    printf '%s\n' "Volume=${CADDYFILE_HOST}:/etc/caddy/Caddyfile:ro,Z"
    printf '%s\n' ''
    printf '%s\n' '[Service]'
    printf '%s\n' 'Restart=on-failure'
    printf '%s\n' 'RestartSec=5'
    printf '%s\n' 'TimeoutStartSec=60'
    printf '%s\n' ''
    printf '%s\n' '[Install]'
    printf '%s\n' 'WantedBy=multi-user.target'
  } >"${out}"
  chmod 644 "${out}"
}

ENV_HOST_PATH="${INSTALL_ROOT}/environment"
if [[ ! -f "${ENV_HOST_PATH}" ]]; then
  sed "s|/opt/containerdata/opnsense-mcp|${INSTALL_ROOT}|g" \
    "${SRC_DIR}/deploy/environment.example" >"${ENV_HOST_PATH}"
  chmod 600 "${ENV_HOST_PATH}"
  echo "Created ${ENV_HOST_PATH} — edit credentials before relying on the service." >&2
fi

if [[ ! -f "${CADDYFILE_HOST}" ]]; then
  cp "${SRC_DIR}/deploy/caddyfile.example" "${CADDYFILE_HOST}"
  chmod 644 "${CADDYFILE_HOST}"
  echo "Wrote ${CADDYFILE_HOST} from deploy/caddyfile.example — confirm PEMs exist under /opt/certs/wild (or edit paths + OPNSENSE_MCP_TLS_CERTS)." >&2
fi

if [[ "$RUNTIME" == "podman" ]]; then
  if ! command -v podman >/dev/null 2>&1; then
    echo "podman not found in PATH (install podman or use --runtime docker)." >&2
    exit 1
  fi
  # Pick up OPNSENSE_MCP_* quadlet settings from the install env file (e.g. re-run or curl|bash without exporting).
  if [[ -f "${ENV_HOST_PATH}" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "${ENV_HOST_PATH}"
    set +a
  fi
  collect_quadlet_settings
  POD_NAME="${OPNSENSE_MCP_POD_NAME}"
  # Quadlet appends "-pod" to the .pod stem to form the unit name: opnsense-mcp.pod → opnsense-mcp-pod.service.
  # So the file is always "opnsense-mcp.pod" (PodName= inside sets the Podman name independently).
  POD_QUADLET_FILE="opnsense-mcp.pod"
  POD_SVC="opnsense-mcp-pod.service"
  # Top-level only: Podman before 4.7 does not recurse into subdirs under /etc/containers/systemd/ (podman#20236).
  # Older installs used .../systemd/opnsense-mcp/ — remove those so 4.7+ never sees duplicate quadlets.
  readonly QUADLET_DIR=/etc/containers/systemd
  readonly LEGACY_QUADLET_SUBDIR=/etc/containers/systemd/opnsense-mcp
  mkdir -p "${QUADLET_DIR}"
  # Quadlet basenames → systemd units (must match Caddy Requires=/After=).
  readonly MCP_QUADLET_BASENAME=opnsense-mcp-app
  readonly CADDY_QUADLET_BASENAME=opnsense-mcp-caddy
  MCP_APP_SVC="${MCP_QUADLET_BASENAME}.service"
  CADDY_SVC="${CADDY_QUADLET_BASENAME}.service"
  rm -f "${LEGACY_QUADLET_SUBDIR}/opnsense-mcp.container" \
    "${LEGACY_QUADLET_SUBDIR}/caddy-opnsense-mcp.container" \
    "${LEGACY_QUADLET_SUBDIR}/opnsense-mcp.pod" \
    "${LEGACY_QUADLET_SUBDIR}/opnsense-mcp-pod.pod" \
    "${LEGACY_QUADLET_SUBDIR}/${POD_NAME}.pod" \
    "${LEGACY_QUADLET_SUBDIR}/${MCP_QUADLET_BASENAME}.container" \
    "${LEGACY_QUADLET_SUBDIR}/${CADDY_QUADLET_BASENAME}.container"
  rmdir "${LEGACY_QUADLET_SUBDIR}" 2>/dev/null || true
  rm -f "${QUADLET_DIR}/opnsense-mcp.container" "${QUADLET_DIR}/caddy-opnsense-mcp.container" \
    "${QUADLET_DIR}/opnsense-mcp-pod.pod"
  echo "Quadlet: dir=${QUADLET_DIR} file=${POD_QUADLET_FILE} PodName=${POD_NAME} systemd=${POD_SVC} MCP=${OPNSENSE_MCP_CONTAINER_NAME} Caddy=${OPNSENSE_MCP_CADDY_CONTAINER_NAME} Image=${IMAGE_REPO}:${IMAGE_TAG} Network=${OPNSENSE_MCP_NETWORK:-} IP=${OPNSENSE_MCP_IP:-} IP6=${OPNSENSE_MCP_IP6:-} DNS=${OPNSENSE_MCP_DNS:-} TLS=${OPNSENSE_MCP_TLS_CERTS}" >&2
  write_opnsense_mcp_pod "${QUADLET_DIR}/${POD_QUADLET_FILE}" "${POD_NAME}"
  write_opnsense_mcp_quadlet "${QUADLET_DIR}/${MCP_QUADLET_BASENAME}.container" "${POD_SVC}" "${POD_QUADLET_FILE}"
  write_caddy_quadlet "${QUADLET_DIR}/${CADDY_QUADLET_BASENAME}.container" "${POD_SVC}" "${MCP_APP_SVC}" "${POD_QUADLET_FILE}"
  "${RUNTIME}" build -f "${SRC_DIR}/deploy/Containerfile" -t "${IMAGE_REPO}:${IMAGE_TAG}" "${SRC_DIR}"
  systemctl daemon-reload
  _pod_load_state=$(systemctl show -p LoadState --value "${POD_SVC}" 2>/dev/null || echo "unknown")
  if [[ "${_pod_load_state}" != "loaded" ]]; then
    echo "warning: ${POD_SVC} not loaded after daemon-reload (LoadState=${_pod_load_state})." >&2
    echo "  Install podman + quadlet support (often package podman-quadlet); check: podman --version (4.4+), journal for quadlet." >&2
  fi
  # Quadlet: enabling the generated .service by name often fails ("transient or generated").
  # Prefer enabling the .container unit files; fall back to start-only.
  enable_or_start_quadlet() {
    local cfile=$1
    local sname=$2
    if systemctl enable "${cfile}" 2>/dev/null; then
      systemctl start "${sname}" || true
    elif systemctl enable --now "${sname}" 2>/dev/null; then
      :
    else
      echo "warning: systemctl enable failed for ${sname}; starting without enable (quadlet)." >&2
      systemctl start "${sname}" || true
    fi
  }
  enable_or_start_quadlet "${QUADLET_DIR}/${POD_QUADLET_FILE}" "${POD_SVC}"
  enable_or_start_quadlet "${QUADLET_DIR}/${MCP_QUADLET_BASENAME}.container" "${MCP_APP_SVC}"
  enable_or_start_quadlet "${QUADLET_DIR}/${CADDY_QUADLET_BASENAME}.container" "${CADDY_SVC}"
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found in PATH" >&2
    exit 1
  fi
  (cd "${SRC_DIR}" && docker compose -p opnsense-mcp -f deploy/docker-compose.yml up -d --build)
fi

echo "Install finished (${RUNTIME})." >&2
echo "  Env:         ${INSTALL_ROOT}/environment" >&2
echo "  Caddyfile:   ${CADDYFILE_HOST}" >&2
if [[ "$RUNTIME" == "podman" ]]; then
  echo "  Quadlets:    /etc/containers/systemd/ (${POD_QUADLET_FILE:-opnsense-mcp.pod}, ${MCP_QUADLET_BASENAME:-opnsense-mcp-app}.container, ${CADDY_QUADLET_BASENAME:-opnsense-mcp-caddy}.container)" >&2
  echo "  Image:       ${IMAGE_REPO}:${IMAGE_TAG}" >&2
fi
echo "Edit credentials and Caddy hostname/TLS paths if you have not already." >&2
