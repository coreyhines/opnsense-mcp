"""Convert pip audit JSON output to HTML format."""

import json
import sys


def main() -> None:
    """
    Convert pip audit JSON output to HTML format.

    Reads JSON from stdin and writes HTML to stdout.
    """
    if len(sys.argv) != 3:
        print("Usage: python3 convert_pip_audit_to_html.py <input.json> <output.html>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        with open(input_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        # Create a simple error report
        html = [
            "<html><head><title>Pip Audit Results</title></head><body>",
            "<h1>Pip Audit Security Report</h1>",
            f"<p>Error reading input file: {e}</p>",
            "<p>No vulnerabilities found or report unavailable.</p>",
            "</body></html>",
        ]
        with open(output_file, "w") as f:
            f.write("\n".join(html))
        return

    html = [
        "<html><head><title>Pip Audit Results</title></head><body>",
        "<h1>Pip Audit Security Report</h1>",
    ]

    if not data:
        html.append("<p>No vulnerabilities found.</p>")
    else:
        html.append("<table border='1'>")
        html.append(
            "<tr><th>Package</th><th>Version</th><th>ID</th><th>Description</th></tr>"
        )

        # Handle different pip-audit output formats
        if isinstance(data, list):
            # Standard format: list of vulnerability objects
            for item in data:
                if isinstance(item, dict):
                    package = item.get("package", "")
                    version = item.get("version", "")
                    vulns = item.get("vulnerabilities", [])

                    if vulns:
                        for vuln in vulns:
                            if isinstance(vuln, dict):
                                html.append(
                                    f"<tr><td>{package}</td>"
                                    f"<td>{version}</td>"
                                    f"<td>{vuln.get('id', '')}</td>"
                                    f"<td>{vuln.get('description', '')}</td></tr>"
                                )
                    else:
                        # Single vulnerability per package
                        html.append(
                            f"<tr><td>{package}</td>"
                            f"<td>{version}</td>"
                            f"<td>{item.get('id', '')}</td>"
                            f"<td>{item.get('description', '')}</td></tr>"
                        )
        elif isinstance(data, dict):
            # Alternative format: dict with vulnerabilities key
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                if isinstance(vuln, dict):
                    html.append(
                        f"<tr><td>{vuln.get('package', '')}</td>"
                        f"<td>{vuln.get('version', '')}</td>"
                        f"<td>{vuln.get('id', '')}</td>"
                        f"<td>{vuln.get('description', '')}</td></tr>"
                    )

        html.append("</table>")

    html.append("</body></html>")

    with open(output_file, "w") as f:
        f.write("\n".join(html))


if __name__ == "__main__":
    main()
