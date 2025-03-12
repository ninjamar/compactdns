import dataclasses
import unittest
from pathlib import Path

from cdns.zones import (DNSZone, MXRecord, SOARecord, ZoneParser,
                        parse_all_zones)

# import cdns.records


class TestZoneParserRecords(unittest.TestCase):
    def test_parse(self):
        path = "/".join(__file__.split("/")[:-2]) + "/example-zones/example.com.zone"
        zones = parse_all_zones(path)

        zones["example.com"] = dataclasses.asdict(zones["example.com"])

        self.assertEqual(
            zones["example.com"],
            {
                "domain": "example.com",
                "ttl": 86400,
                "soa": {
                    "primary_ns": "ns1.example.com.",
                    "admin_email": "admin.example.com.",
                    "serial": 2024022701,
                    "refresh": 3600,
                    "retry": 1800,
                    "expire": 1209600,
                    "minimum": 86400,
                },
                "mx_records": {
                    "@": [
                        {"priority": 10, "exchange": "mail.example.com."},
                        {"priority": 20, "exchange": "backupmail.example.com."},
                    ]
                },
                "records": {
                    "@": {
                        "NS": ["ns1.example.com.", "ns2.example.com."],
                        "TXT": ['"v=spf1 mx -all"'],
                    },
                    "example.com.": {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]},
                    "www": {"A": ["192.0.2.2"]},
                    "mail": {"A": ["192.0.2.3"]},
                    "ftp": {"CNAME": ["www.example.com."]},
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
