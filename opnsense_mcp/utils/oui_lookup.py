"""OUI (Organizationally Unique Identifier) lookup utility for MAC address manufacturers."""

import csv
from pathlib import Path

OUI_CSV_PATH = Path(__file__).parent / "data" / "oui.csv"


class OUILookup:
    """Utility class for looking up MAC address manufacturers from OUI database."""

    def __init__(self, csv_path: Path = OUI_CSV_PATH) -> None:
        """
        Initialize the OUI lookup with CSV data.

        Args:
            csv_path: Path to the OUI CSV file.

        """
        self.oui_map = {}
        self._load_oui_csv(csv_path)

    def _load_oui_csv(self, csv_path: Path) -> None:
        """
        Load OUI data from CSV file.

        Args:
            csv_path: Path to the OUI CSV file.

        """
        if not csv_path.exists():
            raise FileNotFoundError(f"OUI CSV not found at {csv_path}")

        with csv_path.open() as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                assignment = row["Assignment"]
                org_name = row["Organization Name"]
                self.oui_map[assignment] = org_name

    def lookup(self, mac: str) -> str | None:
        """Lookup manufacturer by MAC address (returns None if not found)."""
        mac = mac.lower().replace("-", ":")
        prefix = ":".join(mac.split(":")[:3])
        return self.oui_map.get(prefix)


# Example usage:
# lookup = OUILookup()
# print(lookup.lookup("36:59:41:0f:8c:94"))
