#!/usr/bin/env bash
# Print the hub.freeblizz.com image tag for the current tree or GitLab CI context.
#
# Release (git tag v1.2.3):     1.2.3
# Main / branch (pyproject 1.2.3): 1.2.3-dev.<short-sha>
#
# Usage:
#   ./deploy/ci/compute-image-tag.sh
#   IMAGE_TAG=$(./deploy/ci/compute-image-tag.sh)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pyproject="${repo_root}/pyproject.toml"

if [[ ! -f "${pyproject}" ]]; then
  echo "error: pyproject.toml not found at ${pyproject}" >&2
  exit 1
fi

pyproject_version="$(
  sed -n 's/^version = "\([^"]*\)"/\1/p' "${pyproject}" | head -1
)"
if [[ -z "${pyproject_version}" ]]; then
  echo "error: could not read version from pyproject.toml" >&2
  exit 1
fi

if [[ -n "${CI_COMMIT_TAG:-}" ]]; then
  printf '%s\n' "${CI_COMMIT_TAG#v}"
  exit 0
fi

short_sha="${CI_COMMIT_SHORT_SHA:-}"
if [[ -z "${short_sha}" ]]; then
  short_sha="$(git -C "${repo_root}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

printf '%s\n' "${pyproject_version}-dev.${short_sha}"
