"""Environment loading helpers for OPNsense MCP."""

from __future__ import annotations

import logging
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def load_opnsense_env() -> None:
    """Load environment from legacy and standard dotenv files.

    Supported files (generic file takes precedence):
    - ~/.env
    - ~/.opnsense-env
    """
    candidates = [
        Path.home() / ".env",
        Path.home() / ".opnsense-env",
    ]
    for env_path in candidates:
        if env_path.exists():
            load_dotenv(env_path, override=False)
            logger.debug("Loaded environment file: %s", env_path)
