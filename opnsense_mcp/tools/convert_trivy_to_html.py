"""Convert Trivy JSON output to HTML format."""

import json
import sys


def main() -> None:
    """
    Convert Trivy JSON output to HTML format.

    Reads JSON from stdin and writes HTML to stdout.
    """
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file) as f:
        data = json.load(f)

    html = [
        "<html><head><title>Trivy Results</title></head><body>",
        "<h1>Trivy Security Report</h1>",
    ]

    if not data or not data.get("Results"):
        html.append("<p>No vulnerabilities found.</p>")
    else:
        for result in data.get("Results", []):
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities", [])

            if not vulns:
                continue

            html.append(f"<h2>Target: {target}</h2>")
            html.append("<table border='1'>")
            html.append(
                "<tr><th>Package</th><th>Version</th><th>Vuln ID</th>"
                "<th>Severity</th><th>Title</th><th>Description</th><th>Fix Version</th></tr>"
            )

            # Use list comprehension to build table rows
            table_rows = [
                f"<tr><td>{vuln.get('PkgName', '')}</td>"
                f"<td>{vuln.get('InstalledVersion', '')}</td>"
                f"<td>{vuln.get('VulnerabilityID', '')}</td>"
                f"<td>{vuln.get('Severity', '')}</td>"
                f"<td>{vuln.get('Title', '')}</td>"
                f"<td>{vuln.get('Description', '')[:100]}...</td>"
                f"<td>{vuln.get('FixedVersion', '')}</td></tr>"
                for vuln in vulns
            ]

            html.extend(table_rows)
            html.append("</table>")

    html.append("</body></html>")

    with open(output_file, "w") as f:
        f.write("\n".join(html))


if __name__ == "__main__":
    main()
