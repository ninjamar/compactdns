# compactdns
# A lightweight DNS server with easy customization
# https://github.com/ninjamar/compactdns
# Copyright (c) 2025 ninjamar

# MIT License

# Copyright (c) 2025 ninjamar

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

import dataclasses
from pathlib import Path

from cdns.zones import *

# import cdns.records
root_path = Path(__file__).parent.resolve()


ZONE_PATH = (root_path / "example.com.zone").resolve()


def test_parse():
    zone = parse_file(ZONE_PATH)

    assert dataclasses.asdict(zone) == {
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
            "example.com": [
                {"priority": 10, "exchange": "mail.example.com."},
                {"priority": 20, "exchange": "backupmail.example.com."},
            ]
        },
        "records": {
            "example.com": {
                "NS": [("ns1.example.com.", 86400), ("ns2.example.com.", 86400)],
                "A": [("192.0.2.1", 86400)],
                "AAAA": [("2001:db8::1", 86400)],
                "TXT": [("v=spf1 mx -all", 86400), ("\\ntest\\n", 86400)],
            },
            "www.example.com": {"A": [("192.0.2.2", 86400)]},
            "mail.example.com": {"A": [("192.0.2.3", 86400)]},
            "ftp.example.com": {"CNAME": [("www.example.com.", 86400)]},
        },
    }

