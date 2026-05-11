# Post-deploy MCP smoke test (copy-paste agent prompt)

Use this **after** you rebuild the `opnsense-mcp` container image and restart the service (or redeploy the MCP host). Paste the block below into an assistant that has **OPNsense MCP tools** enabled.

---

## Prompt (copy from here)

You are validating a freshly rebuilt **OPNsense MCP** deployment against a live firewall. The human just restarted the MCP service/container.

**Rules**

1. Use **only** the OPNsense MCP tools (no shell on the firewall unless a tool explicitly uses SSH and the human asked for it).
2. Prefer **read-only** checks. Do **not** create, delete, or toggle firewall rules, DNS records, or DHCP leases unless the human explicitly asks for write tests.
3. If a tool returns `status: error` or an exception, capture the **error message** and continue with the rest of the checklist.
4. Summarize results in a **short table**: tool name → pass/fail → one-line note (counts or error).

**Environment assumption**

The MCP server already has valid `OPNSENSE_FIREWALL_HOST`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET` (and any SSH vars only if you run SSH-dependent tools).

**Checklist — run in order**

1. **System / health** — Call the system status tool (product version, hostname, uptime, or equivalent). Confirm the host matches the intended firewall.
2. **Interfaces** — List interfaces; confirm at least one expected interface name or assignment appears (e.g. WAN/LAN/opt).
3. **Gateway status** — Fetch gateway status; confirm at least one gateway or a clear “none configured” style outcome (not a hard error unless that is unexpected).
4. **Firewall rules (read)** — List firewall filter rules (or search); confirm you get a structured list and a sane count (≥ 0). Note if the response warns about API limits.
5. **ARP/NDP** — Fetch ARP/NDP table; confirm rows or an empty table with success — not an auth/SSL error.
6. **DHCP leases** — Fetch DHCP leases (v4 and/or v6 as available); confirm response shape and that failures are explained (e.g. permissions), not opaque timeouts.
7. **Firewall logs (read)** — Pull a **small** recent slice of firewall logs (limit parameters if the tool supports them). Confirm entries or an empty log with success.
8. **LLDP** — If available, list LLDP neighbors; note “empty” vs “error”.
9. **DNS / aliases (read)** — List DNS records or firewall aliases (whichever tools exist); confirm read path works.

**Optional (only if the human requests SSH or capture tests)**

- **Packet capture / SSH firewall rule tools** — Run only if SSH env is configured and the human asked; report connectivity errors clearly (host, key, port, timeout).

**Deliverable**

Reply with:

- A **table** of each step: Pass / Fail / Skipped + note.
- **One paragraph** overall verdict: ready for use / blocked on credential / blocked on specific tool.
- If anything failed: suggest **one** concrete next check (e.g. API key scope, HTTPS to API, firewall API ACL, or SSH vars for SSH tools).

---

## Maintainer notes

- **When to use:** After image rebuild, compose up, Kubernetes rollout, or systemd restart of the MCP process.
- **Tighten scope:** Add or remove checklist lines to match which tools are actually exposed in your MCP client manifest.
- **Write tests:** Keep destructive checks in a separate prompt; this draft stays read-first to avoid accidents on production.
