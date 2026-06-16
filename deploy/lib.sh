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
    echo "  CI pushes hub.freeblizz.com/opnsense-mcp:<git-short-sha> on main." >&2
    echo "  Example: sudo OPNSENSE_MCP_IMAGE_TAG=82646d9 bash deploy/install.sh" >&2
    exit 1
  fi
  if [[ "${tag}" == "latest" ]]; then
    echo "error: OPNSENSE_MCP_IMAGE_TAG must not be 'latest' (use a git SHA or semver tag)." >&2
    exit 1
  fi
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
