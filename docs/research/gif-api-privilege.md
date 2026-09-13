# GIF API privilege prerequisite

**Symptom:** `GET` or `POST` to `/api/interfaces/gif_settings/*` returns **HTTP 403 Forbidden** (body often `{"status":403,"message":"Forbidden"}`).

**Cause:** The OPNsense user or API key used by MCP lacks permission for GIF device management.

**Fix:** Grant the key **Interfaces → Devices → GIF** access (privilege covering `interfaces:gif_settings`):

1. OPNsense UI: **System → Access → Users** (or **API keys** for the MCP key).
2. Edit the account → **Effective Privileges** (or key privileges).
3. Enable **Interfaces → Devices → GIF** (wording may appear as "GIF" under Devices).
4. Save and retry `GET /api/interfaces/gif_settings/get_item`.

**MCP behaviour until fixed:** GIF interface-device tools must return `status: error` with an explicit privilege message — not an empty success list. Assignment endpoints (`/api/interfaces/assignment/*`) may still work; only gif_settings is blocked.

**Verification:**

```bash
set -a && source ~/.env && set +a
curl -u "${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}" -k -sS \
  "https://${OPNSENSE_FIREWALL_HOST}/api/interfaces/gif_settings/get_item"
```

Expect JSON with a `gif` node, not 403.
