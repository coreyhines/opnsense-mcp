# Shared Forgejo Actions git checkout (inline)
#
# Why not `uses: https://data.forgejo.org/actions/checkout@v6`?
# forgejo-runner copies remote actions into the job container at
# `/var/run/act/actions/...`. Job images (python, alpine, buildah) have
# `/var/run -> /run`. Podman's Docker-compat CopyToContainer then fails with:
#   path escapes from parent
# See moby/moby#53258 / nektos/act#6092 (same class of bug).
#
# Paste the step below after git is installed. Keep REPO_TOKEN from github.token.
# Do NOT leave a `with:` / `fetch-depth` block on a `run:` step — Forgejo
# schema validation rejects it and the whole workflow becomes unusable.
# For full history (was checkout fetch-depth: 0), fetch heads instead of
# `git fetch --depth 1`.

# - name: Checkout
#   env:
#     REPO_TOKEN: ${{ github.token }}
#   run: |
#     set -euo pipefail
#     server="${GITHUB_SERVER_URL:?}"
#     repo="${GITHUB_REPOSITORY:?}"
#     sha="${GITHUB_SHA:?}"
#     token="${REPO_TOKEN:-${GITHUB_TOKEN:-}}"
#     base="${server%/}/${repo}.git"
#     if [ -n "${token}" ]; then
#       origin="https://x-access-token:${token}@${base#https://}"
#     else
#       origin="${base}"
#     fi
#     git init
#     git remote add origin "${origin}"
#     git fetch --depth 1 origin "${sha}"
#     git checkout --force FETCH_HEAD
#     git remote set-url origin "${base}"
