#!/usr/bin/env python3
import requests
import os

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CSV_PATH = os.path.join("opnsense_mcp", "utils", "data", "oui.csv")


def download_oui_csv():
    print(f"Downloading OUI database from {OUI_CSV_URL} ...")
    response = requests.get(OUI_CSV_URL, timeout=10)
    response.raise_for_status()
    os.makedirs(os.path.dirname(OUI_CSV_PATH), exist_ok=True)
    with open(OUI_CSV_PATH, "wb") as f:
        f.write(response.content)
    print(f"OUI database saved to {OUI_CSV_PATH}")


if __name__ == "__main__":
    download_oui_csv()
