#!/usr/bin/env bash
# Run flent rrul from a disposable sidecar on net-10 (wired podman segment).
# Traffic: sidecar -> gw 10.0.10.1 -> OPNsense WAN (fq_codel) -> internet netperf peer.
#
# Usage (on strongpod host):
#   NETPERF_HOST=netperf-west.bufferbloat.net ./deploy/flent-sidecar-net10.sh baseline
#   NETPERF_HOST=netperf-west.bufferbloat.net LABEL=1865down ./deploy/flent-sidecar-net10.sh
#
# Requires: podman, macvlan network "net-10" (same as opnsense-mcp pod).

set -euo pipefail

NET="${FLENT_NET:-net-10}"
GW="${FLENT_GW:-10.0.10.1}"
DNS="${FLENT_DNS:-10.0.2.2}"
NETPERF_HOST="${NETPERF_HOST:-netperf-eu.bufferbloat.net}"
LENGTH="${FLENT_LENGTH:-60}"
RUNS="${FLENT_RUNS:-3}"
LABEL="${LABEL:-${1:-run}}"
OUT_DIR="${FLENT_OUT_DIR:-/opt/containerdata/flent-results}"
IMAGE="${FLENT_IMAGE:-docker.io/library/ubuntu:24.04}"

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FLENT="${OUT_DIR}/${STAMP}_${LABEL}.flent"
OUT_TXT="${OUT_DIR}/${STAMP}_${LABEL}.txt"

echo "=== flent sidecar on ${NET} ==="
echo "peer=${NETPERF_HOST} length=${LENGTH}s runs=${RUNS} label=${LABEL}"
echo "gw=${GW} dns=${DNS}"
echo "output: ${OUT_FLENT}"

# Probe netperf port before a long run
podman run --rm --network "${NET}" --dns "${DNS}" "${IMAGE}" bash -ec "
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq netcat-openbsd >/dev/null
  nc -z -w5 ${NETPERF_HOST} 12865
" || {
  echo "WARN: ${NETPERF_HOST}:12865 not reachable; try netperf-eu.bufferbloat.net" >&2
  exit 1
}

podman run --rm \
  --network "${NET}" \
  --dns "${DNS}" \
  --cap-add=NET_RAW \
  -v "${OUT_DIR}:/out:Z" \
  "${IMAGE}" bash -ec "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq flent netperf iproute2 iputils-ping ca-certificates python3-setuptools >/dev/null
    ip route | head -5
    ping -c 2 ${GW} || true
    flent rrul -H ${NETPERF_HOST} -l ${LENGTH} \
      --batch-repetitions ${RUNS} \
      -t '${LABEL} net-10 via ${GW}' \
      -o /out/$(basename "${OUT_FLENT}") \
      2>&1 | tee /out/$(basename "${OUT_TXT}")
    FLENT_GZ="$(ls -1t /out/*.flent.gz 2>/dev/null | head -1)"
    if [[ -z "${FLENT_GZ}" ]]; then
      echo "error: no .flent.gz output in /out" >&2
      ls -la /out/ >&2 || true
      exit 1
    fi
    SUMMARY_PATH="/out/$(basename "${OUT_TXT}" .txt)_summary.txt"
    flent -i "${FLENT_GZ}" -f summary | tee "${SUMMARY_PATH}"
    cp "${FLENT_GZ}" "/out/$(basename "${OUT_FLENT}").gz"
  "

echo "Done. Flent: ${OUT_FLENT} (see ${OUT_TXT})"
