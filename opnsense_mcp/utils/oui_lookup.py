import csv
import os

OUI_CSV_PATH = os.path.join(os.path.dirname(__file__), "data", "oui.csv")


class OUILookup:
    def __init__(self, csv_path=OUI_CSV_PATH):
        self.oui_map = {}
        self._load_oui_csv(csv_path)

    def _load_oui_csv(self, csv_path):
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"OUI CSV not found at {csv_path}")
        with open(csv_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                assignment = row.get("Assignment", "").replace("-", ":").lower()
                org_name = row.get("Organization Name", "").strip()
                if assignment and org_name:
                    self.oui_map[assignment] = org_name

    def lookup(self, mac):
        """Lookup manufacturer by MAC address (returns None if not found)"""
        mac = mac.lower().replace("-", ":")
        prefix = ":".join(mac.split(":")[:3])
        return self.oui_map.get(prefix)


# Example usage:
# lookup = OUILookup()
# print(lookup.lookup("36:59:41:0f:8c:94"))
