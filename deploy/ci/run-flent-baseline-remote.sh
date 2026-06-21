#!/usr/bin/env bash
# Run flent rrul baseline on strongpod from GitLab CI (SSH + podman sidecar).
set -euo pipefail

DEPLOY_USER="${OPNSENSE_MCP_DEPLOY_USER:-root}"
DEPLOY_HOST="${OPNSENSE_MCP_DEPLOY_HOST:?OPNSENSE_MCP_DEPLOY_HOST is required}"
REMOTE="${DEPLOY_USER}@${DEPLOY_HOST}"

REMOTE_SCRIPT="/opt/containerdata/flent-sidecar-net10.sh"
REMOTE_RESULTS="/opt/containerdata/flent-results"
ARTIFACT_DIR="${CI_PROJECT_DIR:-.}/flent-artifacts"

LABEL="${FLENT_LABEL:-ci-baseline-${CI_PIPELINE_ID:-manual}}"
NETPERF_HOST="${NETPERF_HOST:-netperf-eu.bufferbloat.net}"
FLENT_LENGTH="${FLENT_LENGTH:-60}"
FLENT_RUNS="${FLENT_RUNS:-3}"

mkdir -p "${ARTIFACT_DIR}"

echo "=== Deploy flent sidecar script to ${REMOTE} ==="
scp deploy/flent-sidecar-net10.sh "${REMOTE}:${REMOTE_SCRIPT}"
ssh -o StrictHostKeyChecking=no "${REMOTE}" "chmod +x '${REMOTE_SCRIPT}'"

echo "=== Run flent rrul baseline (label=${LABEL}) ==="
ssh -o StrictHostKeyChecking=no "${REMOTE}" bash -s <<EOF
set -euo pipefail
export NETPERF_HOST='${NETPERF_HOST}'
export FLENT_LENGTH='${FLENT_LENGTH}'
export FLENT_RUNS='${FLENT_RUNS}'
export LABEL='${LABEL}'
'${REMOTE_SCRIPT}' '${LABEL}'
EOF

echo "=== Fetch latest artifacts for label ${LABEL} ==="
LATEST_SUMMARY="$(
  ssh -o StrictHostKeyChecking=no "${REMOTE}" \
    "ls -1t '${REMOTE_RESULTS}'/*_${LABEL}_summary.txt 2>/dev/null | head -1"
)"

if [[ -z "${LATEST_SUMMARY}" ]]; then
  LATEST_SUMMARY="$(
    ssh -o StrictHostKeyChecking=no "${REMOTE}" \
      "ls -1t '${REMOTE_RESULTS}'/*${LABEL}*.flent 2>/dev/null | head -1"
  )"
fi

if [[ -z "${LATEST_SUMMARY}" ]]; then
  echo "error: no flent output found under ${REMOTE_RESULTS} for label ${LABEL}" >&2
  exit 1
fi

BASENAME="$(basename "${LATEST_SUMMARY}")"
scp -o StrictHostKeyChecking=no "${REMOTE}:${LATEST_SUMMARY}" "${ARTIFACT_DIR}/${BASENAME}"

# Best-effort: copy companion .flent.gz and full log when present.
STEM="${BASENAME%_summary.txt}"
STEM="${STEM%.txt}"
for suffix in .flent.gz .flent .txt _summary.txt; do
  REMOTE_FILE="${REMOTE_RESULTS}/${STEM}${suffix}"
  if ssh -o StrictHostKeyChecking=no "${REMOTE}" "test -f '${REMOTE_FILE}'"; then
    scp -o StrictHostKeyChecking=no "${REMOTE}:${REMOTE_FILE}" \
      "${ARTIFACT_DIR}/$(basename "${REMOTE_FILE}")" || true
  fi
done

echo "Fetched summary: ${ARTIFACT_DIR}/${BASENAME}"
printf 'SUMMARY_FILE=%s\n' "${ARTIFACT_DIR}/${BASENAME}" | tee "${ARTIFACT_DIR}/flent.env"
