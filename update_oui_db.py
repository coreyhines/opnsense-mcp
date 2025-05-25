#!/usr/bin/env python3
"""
Script to download and update the OUI database.

This script downloads the OUI (Organizationally Unique Identifier) database
from IEEE and saves it locally for use by the application.
"""

from pathlib import Path

import requests

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CSV_PATH = Path("opnsense_mcp") / "utils" / "data" / "oui.csv"


def download_oui_csv() -> None:
    """Download the latest OUI database from IEEE and save it locally."""
    print(f"Downloading OUI database from {OUI_CSV_URL} ...")
    response = requests.get(OUI_CSV_URL, timeout=10)
    response.raise_for_status()
    OUI_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUI_CSV_PATH.open("wb") as f:
        f.write(response.content)
    print(f"OUI database saved to {OUI_CSV_PATH}")


if __name__ == "__main__":
    download_oui_csv()
