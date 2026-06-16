#!/usr/bin/env bash
# Shared helpers for deploy/install.sh and deploy/uninstall.sh.
set -euo pipefail

readonly DEFAULT_IMAGE_REPO="hub.freeblizz.com/opnsense-mcp"
readonly DEFAULT_CADDY_IMAGE="docker.io/library/caddy:2.9.1-alpine"

is_interactive_shell() {
  local tty_device=/dev/tty
  if [[ -e "${tty_device}" && -r "${tty_device}" ]]; then
    return 0
  fi
  if [[ -t 0 ]]; then
    return 0
  fi
  return 1
}

parse_env_value() {
  local value=$1
  if [[ "${value}" =~ ^\'(.*)\'$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  elif [[ "${value}" =~ ^\"(.*)\"$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    printf '%s' "${value}"
  fi
}

load_environment_file() {
  local file=$1
  local line key raw_value value

  [[ -f "${file}" ]] || return 0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
    [[ "${line}" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"
    raw_value="${BASH_REMATCH[2]}"
    value="$(parse_env_value "${raw_value}")"
    printf -v "${key}" '%s' "${value}"
    export "${key?}"
  done <"${file}"
}

update_env_key() {
  local file=$1 key=$2 value=$3
  local tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "${file}" >"${tmp}" || true
  printf '%s=%s\n' "${key}" "${value}" >>"${tmp}"
  mv "${tmp}" "${file}"
}

validate_pinned_image_tag() {
  local tag=$1
  if [[ -z "${tag}" ]]; then
    echo "error: OPNSENSE_MCP_IMAGE_TAG must be set to a pinned tag (not empty)." >&2
    echo "  Releases: hub.freeblizz.com/opnsense-mcp:<semver> (git tag vX.Y.Z)." >&2
    echo "  Main builds: <semver>-dev.<short-sha> from deploy/ci/compute-image-tag.sh" >&2
    echo "  Example: sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh" >&2
    exit 1
  fi
  if [[ "${tag}" == "latest" ]]; then
    echo "error: OPNSENSE_MCP_IMAGE_TAG must not be 'latest' (use a semver release or -dev tag)." >&2
    exit 1
  fi
  if [[ ! "${tag}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-dev\.[a-zA-Z0-9._-]+)?$ ]]; then
    echo "error: OPNSENSE_MCP_IMAGE_TAG must be semver X.Y.Z or X.Y.Z-dev.<sha> (got: ${tag})." >&2
    exit 1
  fi
}

read_pyproject_version() {
  local pyproject=$1
  sed -n 's/^version = "\([^"]*\)"/\1/p' "${pyproject}" | head -1
}

default_image_tag_for_tree() {
  local src_dir=$1
  bash "${src_dir}/deploy/ci/compute-image-tag.sh"
}

normalize_image_repo() {
  local repo="${IMAGE_REPO:-}"
  repo="${repo#localhost/}"
  if [[ -z "${repo}" ]]; then
    IMAGE_REPO="${DEFAULT_IMAGE_REPO}"
    return 0
  fi
  if [[ "${repo}" == opnsense-mcp ]]; then
    IMAGE_REPO="${DEFAULT_IMAGE_REPO}"
    return 0
  fi
  IMAGE_REPO="${repo}"
}
