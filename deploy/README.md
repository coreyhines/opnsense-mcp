![opnsense-mcp](../docs/assets/logo.png)

# Deploying OPNsense MCP (Streamable HTTP Mode)

Centralized Podman quadlet deployment with **Caddy** TLS and a pinned image from **your registry**.

For local IDE usage (`STDIO`), use the root quickstart instead:
[`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md).

## Fast path

Canonical reference:
[`../docs/CENTRALIZED_DEPLOY_SPEC.md`](../docs/CENTRALIZED_DEPLOY_SPEC.md)

On the host (as root):

```bash
sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh
```

Forgejo Actions on `main` pushes `localhost/opnsense-mcp:<version>-dev.<sha>` (version from `pyproject.toml`).
Git tag `v1.0.0` publishes `localhost/opnsense-mcp:1.0.0`.

After TLS and DNS are in place, clients connect to:

```text
https://mcp.example.com/mcp
```

## Image modes

| Mode | Command |
|------|---------|
| Pull from registry (default) | `sudo bash deploy/install.sh` (auto tag) or `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh` |
| Refresh quadlets only | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --skip-image` |
| Local dev build | `sudo OPNSENSE_MCP_IMAGE_TAG=dev-test bash deploy/install.sh --build-local` |
| Build and push to registry | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --build-push` |

`:latest` is rejected. Tags must be a git short SHA from CI or an explicit semver.

## Runtime summary

- App container runs FastMCP natively (`python3 main.py --transport streamable-http --host 0.0.0.0 --port 8765`).
- App listens on HTTP `8765` inside the pod/network; MCP endpoint is `/mcp`.
- TLS is terminated by Caddy (`deploy/TLS.md`).
- Every HTTP request needs `Authorization: Bearer $MCP_SECRET_KEY`. The app exits at startup when that is blank, or when the `OPNSENSE_*` credentials are blank and `OPNSENSE_USE_MOCK=1` is not set.

## Required follow-ups

- Configure secrets in `environment` (see `environment.example`).
- Configure certs and hostname in [`TLS.md`](TLS.md).
- Set `OPNSENSE_MCP_IMAGE_TAG` to a tag that exists in your registry.

## Releasing to a pinned host, and checking the deploy

The production host's quadlets live in a separate deploy repo, not here, so a new build
reaches it only when someone bumps the pin. Issue #53 was a host left on an
old image after the schema fixes had built.

1. Tag `vX.Y.Z` here. CI builds and pushes `<registry>/opnsense-mcp:X.Y.Z`.
2. Open a PR in the deploy repo changing `Image=` in
   the host's `opnsense-mcp-app.container` to that tag. The owner
   merges it, and that repo's CI deploys.
3. Check the running server, not the build:

   ```bash
   # on the host, inside the container it just started:
   podman exec opnsense-mcp-app python3 -m opnsense_mcp.deploy_smoke \
     --min-tools 15 --expect-version X.Y.Z
   # or from anywhere with the key:
   MCP_SECRET_KEY=... python3 -m opnsense_mcp.deploy_smoke \
     https://<your-hostname>/mcp --min-tools 15 --expect-version X.Y.Z
   ```

   It fails on a stale image (`serverInfo.version` differs) and on any schema
   shape that makes Cursor load zero tools: type unions, arrays without
   `items`, or a property named `constructor`, `__proto__` or `prototype`.
