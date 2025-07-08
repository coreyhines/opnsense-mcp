import json
import sys
from pathlib import Path


def main() -> None:
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    with Path(input_file).open() as f:
        data = json.load(f)

    html = [
        "<html><head><title>Trivy Report</title></head><body>",
        "<h1>Trivy Report</h1>",
    ]
    if not data or not data.get("Results"):
        html.append("<p>No vulnerabilities found.</p>")
    else:
        for result in data.get("Results", []):
            target = result.get("Target", "Unknown Target")
            html.append(f"<h2>{target}</h2>")
            vulns = result.get("Vulnerabilities", [])
            if not vulns:
                html.append("<p>No vulnerabilities found for this target.</p>")
                continue
            html.append(
                "<table border='1'><tr><th>PkgName</th><th>InstalledVersion</th>"
                "<th>VulnID</th><th>Severity</th><th>Title</th><th>Description</th>"
                "<th>FixedVersion</th></tr>"
            )
            for vuln in vulns:
                html.append(
                    f"<tr><td>{vuln.get('PkgName', '')}</td>"
                    f"<td>{vuln.get('InstalledVersion', '')}</td>"
                    f"<td>{vuln.get('VulnerabilityID', '')}</td>"
                    f"<td>{vuln.get('Severity', '')}</td>"
                    f"<td>{vuln.get('Title', '')}</td>"
                    f"<td>{vuln.get('Description', '')[:100]}...</td>"
                    f"<td>{vuln.get('FixedVersion', '')}</td></tr>"
                )
            html.append("</table>")
    html.append("</body></html>")
    with Path(output_file).open("w") as f:
        f.write("\n".join(html))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3.12 convert_trivy_to_html.py input.json output.html")
        sys.exit(1)
    main()
