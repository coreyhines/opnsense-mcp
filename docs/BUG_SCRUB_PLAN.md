# Bug Scrub Plan — OPNsense MCP Server

**Date:** 2026-03-26
**Status:** Pending execution

---

## Phase 1: Critical Bugs (blocking correctness)

### 1.1 Fix duplicate dict key in InterfaceTool
- **File:** `opnsense_mcp/tools/interface.py:128-132`
- **Bug:** `"status"` key appears twice in the return dict. The first assignment (structured status data) is silently overwritten by `"success"` string.
- **Fix:** Rename the first key to `"status_info"` or restructure the return dict so both values are preserved.

### 1.2 Fix missing return in SSHFwRuleTool
- **File:** `opnsense_mcp/tools/ssh_fw_rule.py:111`
- **Bug:** `execute()` awaits `_create_rule_via_ssh()` but never returns the result. Returns `None` on success.
- **Fix:** Add `return result` after the successful await.

### 1.3 Fix asyncio.sleep misuse in API client
- **File:** `opnsense_mcp/utils/api.py:860`
- **Bug:** `asyncio.sleep(0, [])` passes `[]` as the `result` parameter, which becomes the return value. This is used inside `asyncio.gather()` and can break downstream expectations.
- **Fix:** Replace with a trivial async function that returns `[]`, or use a lambda coroutine.

### 1.4 Fix missing _get_client() on SystemTool
- **File:** `opnsense_mcp/tools/system.py:170`
- **Bug:** `diagnose_mcp_server()` calls `self._get_client()` which does not exist on SystemTool. Crashes with `AttributeError`.
- **Fix:** Use `self.client` directly, or add the method if a fresh client is genuinely needed.

### 1.5 Fix bool coercion of "false" string
- **File:** `opnsense_mcp/tools/toggle_fw_rule.py:70`
- **Bug:** `bool(params["enabled"])` converts the string `"false"` to `True` (non-empty string is truthy). Rules get enabled when the caller intended to disable them.
- **Fix:** Parse string values explicitly: `enabled = str(params["enabled"]).lower() in ("true", "1", "yes")`.

### 1.6 Fix operator precedence in DHCP lease matching
- **File:** `opnsense_mcp/tools/dhcp_lease_delete.py:95-102`
- **Bug:** `and`/`or` chain without parentheses relies on implicit operator precedence. Works by accident but is fragile and misleading.
- **Fix:** Add explicit parentheses around each `(field and comparison)` group.

---

## Phase 2: Security and Auth

### 2.1 Remove hardcoded JWT secret
- **File:** `opnsense_mcp/utils/auth.py:13`
- **Bug:** Default secret `"your-secret-key-here"` is used when `JWT_SECRET_KEY` env var is missing. All deployments without the var share the same predictable secret, allowing JWT forgery.
- **Fix:** Raise a startup error if `JWT_SECRET_KEY` is not set. Remove the default value.

### 2.2 Fix deprecated datetime.utcnow()
- **File:** `opnsense_mcp/utils/auth.py:130,132`
- **Bug:** `datetime.utcnow()` is deprecated in Python 3.12 and removed in 3.13. Also, `exp` claim is stored as a datetime object instead of a Unix timestamp.
- **Fix:** Use `datetime.now(timezone.utc)` and convert to int timestamp: `int(expire.timestamp())`.

### 2.3 Add URL decoding in form parser
- **File:** `opnsense_mcp/utils/form_helper.py:35-43`
- **Bug:** URL-encoded form values (e.g. `user%40example.com`) are never decoded. Special characters in usernames/passwords are corrupted.
- **Fix:** Apply `urllib.parse.unquote_plus()` to both keys and values after splitting.

### 2.4 Add recursion depth limit to interface name resolution
- **File:** `opnsense_mcp/tools/firewall.py:53-76`
- **Bug:** `_resolve_interface_name()` recursively calls itself with no depth limit. Circular interface aliases cause `RecursionError`.
- **Fix:** Add a `depth` parameter with a max (e.g. 10) and return the raw name if exceeded.

---

## Phase 3: Concurrency and Resources

### 3.1 Thread-safe HTTP session access
- **File:** `opnsense_mcp/utils/api.py:119-121`
- **Bug:** `requests.Session` is not thread-safe but is used from `run_in_executor()` threads without locking. Concurrent requests can corrupt internal session state.
- **Fix:** Either switch to `aiohttp.ClientSession` (preferred) or wrap session access with a `threading.Lock`.

### 3.2 Add SSH connection timeout
- **File:** `opnsense_mcp/tools/packet_capture.py`
- **Bug:** Paramiko SSH client has no connection timeout. If the SSH server is unresponsive, the tool hangs indefinitely.
- **Fix:** Pass `timeout=10` (or configurable) to `client.connect()`.

### 3.3 Fix logger handler cleanup
- **File:** `opnsense_mcp/utils/logging.py:18`
- **Bug:** `logger.handlers = []` orphans existing handlers without closing them. File handlers don't flush buffers or release file locks.
- **Fix:** Iterate `logger.handlers`, call `.close()` on each, then clear the list.

### 3.4 Add session cleanup to OptimizedOPNsenseClient
- **File:** `opnsense_mcp/utils/api.py:119`
- **Bug:** `requests.Session()` is created at init but never closed. Long-running processes leak TCP connections and file descriptors.
- **Fix:** Add `close()` method and `__enter__`/`__exit__` for context manager usage. Call `self.session.close()` on cleanup.

---

## Phase 4: Test Suite Repair

### 4.1 Remove non-existent tool imports from integration tests
- **File:** `tests/test_integration.py:58-66`
- **Bug:** Imports `ServiceTool`, `VpnTool`, `TrafficTool`, `IdsTool`, `CertificateTool` — none of which exist. The entire integration test suite fails with `ImportError`.
- **Fix:** Remove these imports and their corresponding test functions. Only test tools that actually exist.

### 4.2 Fix fixture scope in test_all_tools.py
- **File:** `tests/test_all_tools.py:28`
- **Bug:** `mock_client` fixture uses `scope="class"`, sharing mutable mock state across all tests. Causes ordering dependencies and false negatives.
- **Fix:** Change to `scope="function"` for proper test isolation.

### 4.3 Remove asyncio.run() from sync test functions
- **File:** `tests/test_all_tools.py:258-260`
- **Bug:** Sync test method uses `asyncio.run()` with nested async functions. Conflicts with pytest-asyncio's event loop management.
- **Fix:** Make the test method `async` and use `@pytest.mark.asyncio`, then `await` directly.

### 4.4 Delete duplicate test files
- **Files:**
  - `tests/test_integration.py` vs `tests/test_integration_clean.py` (nearly identical)
  - `tests/test_standalone.py` vs `tests/test_standalone_clean.py` (nearly identical)
  - `tests/tmp_test_all_tools_fixed.py` (empty placeholder)
- **Fix:** Keep one canonical version of each, delete the duplicates and the empty placeholder.

### 4.5 Add missing methods to MockOPNsenseClient
- **File:** `opnsense_mcp/utils/mock_api.py`
- **Bug:** Missing methods that real tools call: `resolve_host_info()`, `search_arp_table()`, `search_host_overrides()`, `search_aliases()`, `get_lldp_table()`, `search_dhcpv4_leases()`, `search_dhcpv6_leases()`.
- **Fix:** Implement each missing method, returning data from the mock JSON files.

### 4.6 Add error-path tests for all tools
- **Files:** `tests/test_all_tools.py` and new test files as needed
- **Bug:** All existing tests are happy-path only. No tests for: empty params, invalid param types, client exceptions, timeouts, malformed API responses, or None values.
- **Fix:** Add at minimum one error-path test per tool: client raises exception, client returns empty/malformed data.

### 4.7 Add test coverage for untested tools
- **Currently untested (12 tools):**
  1. `tools/get_logs.py`
  2. `tools/mkdns.py`
  3. `tools/rmdns.py`
  4. `tools/set_fw_rule.py`
  5. `tools/ssh_fw_rule.py`
  6. `tools/toggle_fw_rule.py`
  7. `tools/optimized_block.py`
  8. `tools/convert_pip_audit_to_html.py`
  9. `tools/convert_trivy_to_html.py`
  10. `tools/aliases.py`
  11. `tools/dns.py`
  12. `tools/gateway_status.py`
- **Fix:** Write unit tests for each, mocking the API client. Prioritize mutation tools (mkdns, rmdns, set_fw_rule, toggle_fw_rule) as they have the highest risk.

---

## Lower Priority (address opportunistically)

- **Bare `except:` clauses** in multiple tools — narrow to `except Exception:` at minimum
- **LLDP parser** (`utils/api.py:1098-1112`) — add bounds checks on `split()` results
- **Python version pin** (`pyproject.toml:9`) — widen from `<3.13` to `<3.14` after fixing deprecated APIs
- **SSL verification** (`utils/api.py:121,166`) — document the self-signed cert trade-off; consider cert pinning
- **SSH connection reuse** (`tools/ssh_fw_rule.py:85-109`) — pool connections for multi-command sequences
- **Integration test assertion patterns** (`tests/test_integration.py:140+`) — use `is None` checks instead of `if not status` for empty list safety
- **Mock data structure mismatches** — align JSON fixtures with actual tool return schemas
