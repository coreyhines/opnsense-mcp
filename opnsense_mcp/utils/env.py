"""Environment loading helpers for OPNsense MCP."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def _deploy_env_path() -> Path:
    """Host data dir (volume) + ``environment`` — see deploy/opnsense-mcp.container.example."""
    root = os.environ.get(
        "OPNSENSE_MCP_INSTALL_ROOT", "/opt/containerdata/opnsense-mcp"
    )
    return Path(root) / "environment"


def load_opnsense_env() -> None:
    """Load environment from deploy path, optional override file, then home dotenvs.

    Precedence:

    1. ``$OPNSENSE_MCP_INSTALL_ROOT/environment`` (default root
       ``/opt/containerdata/opnsense-mcp``) if the file exists (override=True).
    2. Path in ``OPNSENSE_ENV_FILE`` if set and the file exists (override=True).
    3. ``~/.env`` then ``~/.opnsense-env`` (override=False — only fills unset keys).

    Later steps (3) do not override keys already set by (1) or (2).
    """
    deploy_env = _deploy_env_path()
    if deploy_env.exists():
        load_dotenv(deploy_env, override=True)
        logger.debug("Loaded environment file: %s", deploy_env)
    extra = os.environ.get("OPNSENSE_ENV_FILE", "").strip()
    if extra:
        p = Path(extra)
        if p.exists():
            load_dotenv(p, override=True)
            logger.debug("Loaded environment file: %s", p)
    candidates = [
        Path.home() / ".env",
        Path.home() / ".opnsense-env",
    ]
    for env_path in candidates:
        if env_path.exists():
            load_dotenv(env_path, override=False)
            logger.debug("Loaded environment file: %s", env_path)
