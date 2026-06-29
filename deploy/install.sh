#!/usr/bin/env bash
# OPNsense MCP centralized install (Linux amd64). Pulls a pinned image from hub.freeblizz.com.
# Idempotent: safe to re-run (refresh quadlets, pull image, systemd reload).
#
#   sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh
#
# One-liner (auto tag from pyproject + git sha on main):
#   curl -fsSL 'https://gitlab.freeblizz.com/coreyhines/opnsense-mcp/-/raw/main/deploy/install.sh' | sudo bash
#
# Local dev build (does not push):
#   sudo OPNSENSE_MCP_IMAGE_TAG=dev-$(git rev-parse --short HEAD) bash deploy/install.sh --build-local
#
set -euo pipefail

readonly DEFAULT_REPO_URL="${OPNSENSE_MCP_REPO_URL:-https://gitlab.freeblizz.com/coreyhines/opnsense-mcp.git}"
readonly GIT_REF="${OPNSENSE_MCP_GIT_REF:-main}"
readonly INSTALL_ROOT="${OPNSENSE_MCP_INSTALL_ROOT:-/opt/containerdata/opnsense-mcp}"
readonly SRC_DIR="${INSTALL_ROOT}/src"
readonly CADDYFILE_HOST="${INSTALL_ROOT}/Caddyfile"

IMAGE_REPO="${OPNSENSE_MCP_IMAGE_REPO:-hub.freeblizz.com/opnsense-mcp}"
EXPLICIT_IMAGE_TAG="${OPNSENSE_MCP_IMAGE_TAG:-}"
IMAGE_TAG="${EXPLICIT_IMAGE_TAG}"
CADDY_IMAGE="${OPNSENSE_MCP_CADDY_IMAGE:-docker.io/library/caddy:2.9.1-alpine}"
RUNTIME="${OPNSENSE_MCP_RUNTIME:-podman}"
SKIP_IMAGE=0
BUILD_LOCAL=0
BUILD_PUSH=0

usage() {
  echo "Usage: $0 [--runtime podman|docker] [--skip-image] [--build-local] [--build-push]" >&2
  echo "  Default: pull hub.freeblizz.com/opnsense-mcp:\$OPNSENSE_MCP_IMAGE_TAG (pinned tag required)." >&2
  echo "  Env: OPNSENSE_MCP_IMAGE_REPO (default hub.freeblizz.com/opnsense-mcp)" >&2
  echo "       OPNSENSE_MCP_IMAGE_TAG (required unless already in environment file)" >&2
  echo "       OPNSENSE_MCP_CADDY_IMAGE (default docker.io/library/caddy:2.9.1-alpine)" >&2
  echo "       OPNSENSE_MCP_REPO_URL, OPNSENSE_MCP_GIT_REF, OPNSENSE_MCP_INSTALL_ROOT" >&2
  echo "  Quadlet: OPNSENSE_MCP_POD_NAME, OPNSENSE_MCP_CONTAINER_NAME," >&2
  echo "    OPNSENSE_MCP_CADDY_CONTAINER_NAME, OPNSENSE_MCP_NETWORK, OPNSENSE_MCP_IP," >&2
  echo "    OPNSENSE_MCP_IP6, OPNSENSE_MCP_DNS, OPNSENSE_MCP_TLS_CERTS" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      RUNTIME="${2:-}"
      if [[ -z "${RUNTIME}" ]]; then echo "--runtime needs a value" >&2; exit 1; fi
      shift 2
      ;;
    --skip-image) SKIP_IMAGE=1; shift ;;
    --build-local) BUILD_LOCAL=1; shift ;;
    --build-push) BUILD_PUSH=1; shift ;;
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

if [[ "${BUILD_LOCAL}" -eq 1 && "${BUILD_PUSH}" -eq 1 ]]; then
  echo "error: use only one of --build-local or --build-push" >&2
  exit 1
fi

echo "opnsense-mcp install: INSTALL_ROOT=${INSTALL_ROOT} SRC_DIR=${SRC_DIR} GIT_REF=${GIT_REF} RUNTIME=${RUNTIME} IMAGE=${IMAGE_REPO}:${IMAGE_TAG:-<unset>}" >&2

mkdir -p "${INSTALL_ROOT}" /etc/containers/systemd/opnsense-mcp

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${GIT_REF}" "${DEFAULT_REPO_URL}" "${SRC_DIR}"
else
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

# shellcheck source=lib.sh
source "${SRC_DIR}/deploy/lib.sh"
normalize_image_repo

collect_image_settings() {
  local tty_device=/dev/tty

  if [[ -z "${IMAGE_TAG}" && -f "${ENV_HOST_PATH}" ]]; then
    load_environment_file "${ENV_HOST_PATH}"
    IMAGE_TAG="${OPNSENSE_MCP_IMAGE_TAG:-}"
    IMAGE_REPO="${OPNSENSE_MCP_IMAGE_REPO:-${IMAGE_REPO}}"
    CADDY_IMAGE="${OPNSENSE_MCP_CADDY_IMAGE:-${CADDY_IMAGE}}"
    normalize_image_repo
  fi

  if [[ -z "${IMAGE_TAG}" && -f "${SRC_DIR}/pyproject.toml" ]]; then
    IMAGE_TAG="$(default_image_tag_for_tree "${SRC_DIR}")"
    echo "Auto-selected image tag: ${IMAGE_TAG}" >&2
  fi

  if is_interactive_shell && [[ -z "${EXPLICIT_IMAGE_TAG}" ]]; then
    local suggested="${IMAGE_TAG:-}"
    if [[ -z "${suggested}" && -f "${SRC_DIR}/pyproject.toml" ]]; then
      suggested="$(default_image_tag_for_tree "${SRC_DIR}")"
    fi
    read -r -p "Pinned image tag [${suggested}]: " _tag <"${tty_device}" || true
    if [[ -n "${_tag}" ]]; then
      IMAGE_TAG="${_tag}"
    else
      IMAGE_TAG="${suggested}"
    fi
  fi

  validate_pinned_image_tag "${IMAGE_TAG}"
}

collect_quadlet_settings() {
  local tty_device=/dev/tty
  local interactive=0
  if is_interactive_shell; then
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
    printf '%s\n' 'Description=OPNsense MCP (Podman quadlet, FastMCP Streamable HTTP)'
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
    printf '%s\n' "Image=${CADDY_IMAGE}"
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

build_image() {
  local version_full="${IMAGE_REPO}:${IMAGE_TAG}"
  local build_git_commit
  local build_time
  build_git_commit="$(git -C "${SRC_DIR}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Building ${version_full} (git_commit=${build_git_commit} git_ref=${GIT_REF} build_time=${build_time})..." >&2
  "${RUNTIME}" build -f "${SRC_DIR}/deploy/Containerfile" -t "${version_full}" \
    --build-arg "GIT_COMMIT=${build_git_commit}" \
    --build-arg "GIT_REF=${GIT_REF}" \
    --build-arg "BUILD_TIME=${build_time}" \
    "${SRC_DIR}"
}

push_image() {
  local version_full="${IMAGE_REPO}:${IMAGE_TAG}"
  echo "Pushing ${version_full}..." >&2
  "${RUNTIME}" push "${version_full}"
}

pull_image() {
  local version_full="${IMAGE_REPO}:${IMAGE_TAG}"
  echo "Pulling ${version_full}..." >&2
  "${RUNTIME}" pull "${version_full}"
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
  if [[ -f "${ENV_HOST_PATH}" ]]; then
    load_environment_file "${ENV_HOST_PATH}"
  fi
  collect_image_settings
  collect_quadlet_settings
  POD_NAME="${OPNSENSE_MCP_POD_NAME}"
  POD_QUADLET_FILE="opnsense-mcp.pod"
  POD_SVC="opnsense-mcp-pod.service"
  readonly QUADLET_DIR=/etc/containers/systemd
  readonly LEGACY_QUADLET_SUBDIR=/etc/containers/systemd/opnsense-mcp
  mkdir -p "${QUADLET_DIR}"
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
  echo "Quadlet: dir=${QUADLET_DIR} file=${POD_QUADLET_FILE} PodName=${POD_NAME} systemd=${POD_SVC} MCP=${OPNSENSE_MCP_CONTAINER_NAME} Caddy=${OPNSENSE_MCP_CADDY_CONTAINER_NAME} Image=${IMAGE_REPO}:${IMAGE_TAG} CaddyImage=${CADDY_IMAGE} Network=${OPNSENSE_MCP_NETWORK:-} IP=${OPNSENSE_MCP_IP:-} IP6=${OPNSENSE_MCP_IP6:-} DNS=${OPNSENSE_MCP_DNS:-} TLS=${OPNSENSE_MCP_TLS_CERTS}" >&2
  write_opnsense_mcp_pod "${QUADLET_DIR}/${POD_QUADLET_FILE}" "${POD_NAME}"
  write_opnsense_mcp_quadlet "${QUADLET_DIR}/${MCP_QUADLET_BASENAME}.container" "${POD_SVC}" "${POD_QUADLET_FILE}"
  write_caddy_quadlet "${QUADLET_DIR}/${CADDY_QUADLET_BASENAME}.container" "${POD_SVC}" "${MCP_APP_SVC}" "${POD_QUADLET_FILE}"

  update_env_key "${ENV_HOST_PATH}" "OPNSENSE_MCP_IMAGE_REPO" "${IMAGE_REPO}"
  update_env_key "${ENV_HOST_PATH}" "OPNSENSE_MCP_IMAGE_TAG" "${IMAGE_TAG}"
  update_env_key "${ENV_HOST_PATH}" "OPNSENSE_MCP_CADDY_IMAGE" "${CADDY_IMAGE}"

  if [[ "${SKIP_IMAGE}" -eq 1 ]]; then
    echo "Skipping image pull/build (--skip-image)." >&2
  elif [[ "${BUILD_PUSH}" -eq 1 ]]; then
    build_image
    push_image
  elif [[ "${BUILD_LOCAL}" -eq 1 ]]; then
    build_image
  else
    pull_image
    "${RUNTIME}" pull "${CADDY_IMAGE}" || true
  fi

  systemctl daemon-reload
  _pod_load_state=$(systemctl show -p LoadState --value "${POD_SVC}" 2>/dev/null || echo "unknown")
  if [[ "${_pod_load_state}" != "loaded" ]]; then
    echo "warning: ${POD_SVC} not loaded after daemon-reload (LoadState=${_pod_load_state})." >&2
    echo "  Install podman + quadlet support (often package podman-quadlet); check: podman --version (4.4+), journal for quadlet." >&2
  fi
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
  (cd "${SRC_DIR}" && docker compose -p opnsense-mcp -f deploy/docker-compose.yml up -d --build \
    --build-arg "GIT_COMMIT=$(git -C "${SRC_DIR}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)" \
    --build-arg "GIT_REF=${GIT_REF}" \
    --build-arg "BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)")
fi

echo "Install finished (${RUNTIME})." >&2
echo "  Env:         ${INSTALL_ROOT}/environment" >&2
echo "  Caddyfile:   ${CADDYFILE_HOST}" >&2
if [[ "$RUNTIME" == "podman" ]]; then
  echo "  Quadlets:    /etc/containers/systemd/ (${POD_QUADLET_FILE:-opnsense-mcp.pod}, ${MCP_QUADLET_BASENAME:-opnsense-mcp-app}.container, ${CADDY_QUADLET_BASENAME:-opnsense-mcp-caddy}.container)" >&2
  echo "  Image:       ${IMAGE_REPO}:${IMAGE_TAG}" >&2
fi
echo "Edit credentials and Caddy hostname/TLS paths if you have not already." >&2
