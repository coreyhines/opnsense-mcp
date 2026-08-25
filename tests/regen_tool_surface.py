"""Regenerate the golden tool-surface snapshot.

    uv run python -m tests.regen_tool_surface

Run this only when a surface change is intended, and commit the result with the
change that caused it. Regenerating to turn a red test green defeats the point:
the snapshot exists so the registry refactor and the shaper regrouping cannot
alter the caller-facing contract without it showing up in review.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.tool_surface import GOLDEN, current_surface


def main() -> None:
    surface = current_surface()
    Path(GOLDEN).write_text(json.dumps(surface, indent=2, sort_keys=True) + "\n")
    print(f"wrote {GOLDEN} with {len(surface)} tools")


if __name__ == "__main__":
    main()
