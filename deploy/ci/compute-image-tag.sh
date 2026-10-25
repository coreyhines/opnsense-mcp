#!/usr/bin/env bash
# Print the image tag for the current tree or Forgejo Actions context.
#
# Release (git tag v1.2.3):        1.2.3
# Main / branch (pyproject 1.2.3): 1.2.4-dev.<short-sha>
#
# pyproject holds the last released version, so a dev build is a prerelease
# of the next patch. Tagging it 1.2.3-dev ranked it below 1.2.3 in semver,
# and a deployer treated the older release as an upgrade.
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
  release="${CI_COMMIT_TAG#v}"
  # Dev tags assume pyproject equals the last release; enforce it here.
  if [[ "${release}" != "${pyproject_version}" ]]; then
    echo "error: tag ${CI_COMMIT_TAG} does not match pyproject version ${pyproject_version}" >&2
    exit 1
  fi
  printf '%s\n' "${release}"
  exit 0
fi

if [[ ! "${pyproject_version}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "error: pyproject version ${pyproject_version} is not X.Y.Z" >&2
  exit 1
fi
next_patch="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"

short_sha="${CI_COMMIT_SHORT_SHA:-}"
if [[ -z "${short_sha}" ]]; then
  short_sha="$(git -C "${repo_root}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

printf '%s\n' "${next_patch}-dev.${short_sha}"
