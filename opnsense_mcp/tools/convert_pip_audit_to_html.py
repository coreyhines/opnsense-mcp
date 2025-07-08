"""Convert pip audit JSON output to HTML format."""

import json
import sys


def main() -> None:
    """
    Convert pip audit JSON output to HTML format.

    Reads JSON from stdin and writes HTML to stdout.
    """
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file) as f:
        data = json.load(f)

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

        for item in data:
            package = item.get("package", "")
            version = item.get("version", "")
            vulns = item.get("vulnerabilities", [])

            for vuln in vulns:
                html.append(
                    f"<tr><td>{package}</td>"
                    f"<td>{version}</td>"
                    f"<td>{vuln.get('id', '')}</td>"
                    f"<td>{vuln.get('description', '')}</td></tr>"
                )

        html.append("</table>")

    html.append("</body></html>")

    with open(output_file, "w") as f:
        f.write("\n".join(html))


if __name__ == "__main__":
    main()
