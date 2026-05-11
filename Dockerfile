# Glama and local stdio MCP: build from repo root.
# SSE + mcp-proxy image: see deploy/Containerfile
#
#   podman build -t opnsense-mcp:stdio .
#   podman run --rm -i opnsense-mcp:stdio

FROM docker.io/library/python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_TRANSPORT=stdio

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY opnsense_mcp ./opnsense_mcp
COPY examples ./examples
COPY main.py ./

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH=/app

# Smoke: imports must succeed (Glama-style sanity check)
RUN python3 -c "from opnsense_mcp.server import main as _m; print('import ok')"

CMD ["python3", "main.py"]
