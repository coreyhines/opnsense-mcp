import json
import sys
from pathlib import Path


def main() -> None:
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    with Path(input_file).open() as f:
        data = json.load(f)

    html = [
        "<html><head><title>pip-audit Report</title></head><body>",
        "<h1>pip-audit Report</h1>",
    ]
    if not data or isinstance(data, str):
        html.append(f"<p>{data if data else 'No vulnerabilities found.'}</p>")
    else:
        html.append(
            "<table border='1'><tr><th>Package</th><th>Version</th>"
            "<th>Vuln ID</th><th>Description</th><th>Fix Version</th></tr>"
        )
        for entry in data:
            pkg = entry.get("name", "")
            version = entry.get("version", "")
            for vuln in entry.get("vulns", []):
                vuln_id = vuln.get("id", "")
                desc = vuln.get("description", "")
                fix = (
                    vuln.get("fix_versions", [""])[0]
                    if vuln.get("fix_versions")
                    else ""
                )
                html.append(
                    f"<tr><td>{pkg}</td><td>{version}</td><td>{vuln_id}</td>"
                    f"<td>{desc}</td><td>{fix}</td></tr>"
                )
        html.append("</table>")
    html.append("</body></html>")
    with Path(output_file).open("w") as f:
        f.write("\n".join(html))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3.12 convert_pip_audit_to_html.py input.json output.html")
        sys.exit(1)
    main()
