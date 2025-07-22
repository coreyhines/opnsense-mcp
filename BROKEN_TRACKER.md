# Broken Features Tracker

This file tracks features or tools that are currently broken or not working as expected, for future follow-up and resolution.

---

## 2025-07-10

### OPNsense Firewall Log Retrieval
- **Issue:** The tool for retrieving recent OPNsense firewall logs (`mcp_opnsense-mcp_get_logs`) does not return any results, even when requested multiple times.
- **Status:** **FIXED** as of 2025-07-11. The backend and server were updated to use the correct API endpoint, parse the log format, and return results in the client-expected schema. End-to-end log retrieval is now working.
- **Symptoms:** No logs are returned, and no error message is provided to clarify the failure.
- **Next Steps:** Investigate the backend implementation, check API connectivity, and review OPNsense API documentation for log retrieval endpoints and permissions.

---

## 2025-07-11

### mkfw_rule Tool - Rules Not Enforced
- **Issue:** The mkfw_rule tool successfully creates firewall rules, but the rules do not actually get enforced by OPNsense.
- **Symptoms:** Rules appear in the UI as expected, but traffic is not blocked or allowed as specified by the rule.
- **Next Steps:** Investigate why created rules are not enforced, check rule placement, floating vs. interface rules, and OPNsense rule processing logic. Further attention required.

---

_Add additional issues below as they are discovered._ 
