# opnsense-mcp — Recent Features (PRs #19–#24)

Five pull requests landed in June 2026. This doc covers what changed, why it matters, and how to use each capability.

---

## 1. Streamable HTTP Transport (MCP spec 2025-03-26)

**PR:** [#20](https://github.com/coreyhines/opnsense-mcp/pull/20)  
**Commit:** `dd51949`

### What changed

Added a native [FastMCP](https://github.com/jlowin/fastmcp) server (`opnsense_mcp/fastmcp_server.py`) that registers all 26 OPNsense tools and supports three transports:

| Transport | Best for | Endpoint / invocation |
|-----------|----------|-----------------------|
| `stdio` | Local IDE (Cursor, Claude Code, Continue) | `python main.py` |
| `sse` | Backward-compatible centralized clients | `/sse` |
| `streamable-http` | Modern MCP clients (spec 2025-03-26) | `/mcp` |

The existing stdio server is untouched; existing SSE deployments continue to work. Streamable HTTP is the new default for centralized installs.

### Usage

Local (stdio — unchanged):
```bash
python main.py
```

Centralized Streamable HTTP:
```bash
python main.py --transport streamable-http --host 0.0.0.0 --port 8765
```

Clients connect to:
```text
https://opnsense-mcp.freeblizz.com/mcp
```

Deployment scripts already default to Streamable HTTP; no manual flag is needed when using `deploy/install.sh`.

---

## 2. DHCP client_id (DUID) Support for Host Reservations

**PR:** [#21](https://github.com/coreyhines/opnsense-mcp/pull/21)  
**Commit:** `82646d9`

### What changed

`mk_dhcp_host` and `move_dhcp_host` now accept an optional `client_id` parameter. This is the DHCP Unique Identifier (DUID) used for stateful DHCPv6 matching. Some IPv6 clients are not reliably matched by MAC address alone; supplying the DUID ensures the reservation applies correctly.

- Accepts hex strings like `00:03:00:01:52:54:00:ab:cd:01`
- Optional `id:` prefix is normalized automatically
- Duplicate DUID detection prevents conflicting reservations

### Usage examples

Create a reservation with a DUID:
```json
{
  "hostname": "printer-lan",
  "mac": "aa:bb:cc:dd:ee:ff",
  "ipv4": "10.0.8.50",
  "client_id": "00:03:00:01:52:54:00:ab:cd:01",
  "apply": true
}
```

Move a reservation and update its DUID:
```json
{
  "host": "printer-lan",
  "ipv4": "10.0.8.55",
  "client_id": "00:03:00:01:52:54:00:ab:cd:02",
  "apply": true
}
```

To find a client’s DUID, query the `dhcp` tool and look for the `client_id` field in IPv6 leases.

---

## 3. Semver Image Tags from pyproject and Git Releases

**Merged via MR !21**  
**Commit:** `b80b327`

### What changed

Container images are now tagged with deterministic semver instead of floating `latest`.

| Source | Tag format | Example |
|--------|-----------|---------|
| `main` branch (CI) | `<pyproject-version>-dev.<short-sha>` | `1.0.0-dev.a1b2c3d` |
| Git tag `vX.Y.Z` | `X.Y.Z` | `1.0.0` |

The helper script `deploy/ci/compute-image-tag.sh` reads `version` from `pyproject.toml` and appends the git short SHA for non-tag builds. This makes every image traceable to a commit.

### Release workflow

1. Bump `version` in `pyproject.toml`.
2. Commit and push to `main`.
3. Tag and push: `git tag v1.0.1 && git push origin v1.0.1`
4. GitLab CI publishes `hub.freeblizz.com/opnsense-mcp:1.0.1`.

---

## 4. hub.freeblizz.com Registry with Pinned Tags

**PR:** [#23](https://github.com/coreyhines/opnsense-mcp/pull/23)  
**Commit:** `24f13d2`

### What changed

The deployment moved from local host builds (`localhost:latest`) to a proper container registry:

- **Registry:** `hub.freeblizz.com/opnsense-mcp`
- **Requirement:** `OPNSENSE_MCP_IMAGE_TAG` must be a pinned tag (semver or short SHA)
- `:latest` is explicitly rejected

Installer modes:

| Mode | Command |
|------|---------|
| Pull from registry (default) | `sudo bash deploy/install.sh` |
| Explicit tag | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh` |
| Refresh quadlets only | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --skip-image` |
| Local dev build | `sudo OPNSENSE_MCP_IMAGE_TAG=dev-test bash deploy/install.sh --build-local` |
| Build and push | `sudo OPNSENSE_MCP_IMAGE_TAG=1.0.0 bash deploy/install.sh --build-push` |

CI uses Kaniko to build and push images. A manual `deploy:strongpod` job is available for pushing to a specific host after a successful CI build.

---

## 5. Readonly Clash Fix in install.sh

**PR:** [#24](https://github.com/coreyhines/opnsense-mcp/pull/24)  
**Commit:** `6845616`

### What changed

Both `deploy/install.sh` and `deploy/lib.sh` declared `DEFAULT_IMAGE_REPO` as `readonly`. When `install.sh` sourced `lib.sh`, Bash threw a `readonly variable` error and the install aborted.

Fix: removed the duplicate `readonly` declaration and related registry-login hints from `install.sh`. The canonical value now lives only in `lib.sh`.

Impact: existing `curl | bash` one-liners and manual installs now complete without the clash.

---

## Summary Table

| Feature | PR | Files touched | User-visible change |
|---------|-----|---------------|---------------------|
| Streamable HTTP | #20 | `fastmcp_server.py`, `main.py`, deploy docs | Native `/mcp` endpoint; SSE still works |
| DHCP client_id | #21 | `mk_dhcp_host.py`, `dhcp_host_move.py`, `utils/dhcp_host.py`, tests | IPv6 DUID support in reservations |
| Semver tags | MR !21 | `deploy/ci/compute-image-tag.sh`, CI config, install scripts | Traceable `X.Y.Z-dev.<sha>` images |
| Registry + pinned tags | #23 | `deploy/install.sh`, `deploy/lib.sh`, `deploy/README.md`, CI | `hub.freeblizz.com/opnsense-mcp:<tag>` |
| Readonly clash fix | #24 | `deploy/install.sh`, `deploy/README.md` | Install completes without Bash errors |

---

## Related docs

- [`deploy/README.md`](https://github.com/coreyhines/opnsense-mcp/blob/main/deploy/README.md) — deployment quickstart
- [`docs/CENTRALIZED_DEPLOY_SPEC.md`](https://github.com/coreyhines/opnsense-mcp/blob/main/docs/CENTRALIZED_DEPLOY_SPEC.md) — full architecture and spec
- [`deploy/install.sh`](https://github.com/coreyhines/opnsense-mcp/blob/main/deploy/install.sh) — installer script
