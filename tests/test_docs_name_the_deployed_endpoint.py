"""Documentation must give clients the endpoint the deployment serves.

Docs advertised `https://<host>/sse`, while the deployed container runs
`--transport streamable-http` and answers 404 there (issue #54). A sweep
would miss the next file, so this walks every tracked markdown and example.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_SSE_URL = re.compile(r"https?://\S+/sse\b")


def _tracked_docs() -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "*.md", "*.example", "*.example.*"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [
        REPO / line
        for line in out.splitlines()
        if line.strip() and not line.startswith("docs/research/")
    ]


def test_the_container_serves_streamable_http() -> None:
    """The premise: what the image actually runs."""
    containerfile = (REPO / "deploy" / "Containerfile").read_text()
    cmd = next(line for line in containerfile.splitlines() if line.startswith("CMD"))
    assert '"streamable-http"' in cmd


def test_no_doc_offers_an_sse_url() -> None:
    stale = [
        f"{path.relative_to(REPO)}:{n}: {line.strip()}"
        for path in _tracked_docs()
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if _SSE_URL.search(line)
    ]
    assert not stale, (
        "docs offer an /sse URL the deployment does not serve: " + "; ".join(stale)
    )
