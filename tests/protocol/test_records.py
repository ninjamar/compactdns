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
from cdns.server.storage import RecordStorage, RTypes

# import cdns.records
root_path = Path(__file__).parent.resolve()


ZONE_PATH = (root_path / "example.com.zone").resolve()
ROOT_PATH = (root_path / "named.root").resolve()


def test_records():
    storage = RecordStorage()

    storage.load_zone_from_file(ZONE_PATH)
    storage.load_zone_from_file(ROOT_PATH)
    assert storage.zones == {
        "example.com": DNSZone(
            domain="example.com",
            ttl=86400,
            soa=SOARecord(
                primary_ns="ns1.example.com.",
                admin_email="admin.example.com.",
                serial=2024022701,
                refresh=3600,
                retry=1800,
                expire=1209600,
                minimum=86400,
            ),
            mx_records={
                "example.com": [
                    MXRecord(priority=10, exchange="mail.example.com"),
                    MXRecord(priority=20, exchange="backupmail.example.com"),
                ]
            },
            records={
                "example.com": {
                    "NS": [("ns1.example.com", 86400), ("ns2.example.com", 86400)],
                    "A": [("192.0.2.1", 86400)],
                    "AAAA": [("2001:db8::1", 86400)],
                    "TXT": [("v=spf1 mx -all", 86400), ("\\ntest\\n", 86400)],
                },
                "www.example.com": {"A": [("192.0.2.2", 86400)]},
                "mail.example.com": {"A": [("192.0.2.3", 86400)]},
                "ftp.example.com": {"CNAME": [("www.example.com", 86400)]},
            },
        ),
        "": DNSZone(
            domain="",
            ttl=3600,
            soa=None,
            mx_records={},
            records={
                "": {
                    "NS": [
                        ("a.root-servers.net", 3600000),
                        ("b.root-servers.net", 3600000),
                        ("c.root-servers.net", 3600000),
                        ("d.root-servers.net", 3600000),
                        ("e.root-servers.net", 3600000),
                        ("f.root-servers.net", 3600000),
                        ("g.root-servers.net", 3600000),
                        ("h.root-servers.net", 3600000),
                        ("i.root-servers.net", 3600000),
                        ("j.root-servers.net", 3600000),
                        ("k.root-servers.net", 3600000),
                        ("l.root-servers.net", 3600000),
                        ("m.root-servers.net", 3600000),
                    ]
                },
                "a.root-servers.net": {
                    "A": [("198.41.0.4", 3600000)],
                    "AAAA": [("2001:503:ba3e::2:30", 3600000)],
                },
                "b.root-servers.net": {
                    "A": [("170.247.170.2", 3600000)],
                    "AAAA": [("2801:1b8:10::b", 3600000)],
                },
                "c.root-servers.net": {
                    "A": [("192.33.4.12", 3600000)],
                    "AAAA": [("2001:500:2::c", 3600000)],
                },
                "d.root-servers.net": {
                    "A": [("199.7.91.13", 3600000)],
                    "AAAA": [("2001:500:2d::d", 3600000)],
                },
                "e.root-servers.net": {
                    "A": [("192.203.230.10", 3600000)],
                    "AAAA": [("2001:500:a8::e", 3600000)],
                },
                "f.root-servers.net": {
                    "A": [("192.5.5.241", 3600000)],
                    "AAAA": [("2001:500:2f::f", 3600000)],
                },
                "g.root-servers.net": {
                    "A": [("192.112.36.4", 3600000)],
                    "AAAA": [("2001:500:12::d0d", 3600000)],
                },
                "h.root-servers.net": {
                    "A": [("198.97.190.53", 3600000)],
                    "AAAA": [("2001:500:1::53", 3600000)],
                },
                "i.root-servers.net": {
                    "A": [("192.36.148.17", 3600000)],
                    "AAAA": [("2001:7fe::53", 3600000)],
                },
                "j.root-servers.net": {
                    "A": [("192.58.128.30", 3600000)],
                    "AAAA": [("2001:503:c27::2:30", 3600000)],
                },
                "k.root-servers.net": {
                    "A": [("193.0.14.129", 3600000)],
                    "AAAA": [("2001:7fd::1", 3600000)],
                },
                "l.root-servers.net": {
                    "A": [("199.7.83.42", 3600000)],
                    "AAAA": [("2001:500:9f::42", 3600000)],
                },
                "m.root-servers.net": {
                    "A": [("202.12.27.33", 3600000)],
                    "AAAA": [("2001:dc3::35", 3600000)],
                },
            },
        ),
    }

    assert storage.get_record(type_=RTypes.A, record_domain="example.com") == [
        ("192.0.2.1", 86400)
    ]
    assert storage.get_record(type_=RTypes.NS, record_domain="") == [
        ("a.root-servers.net", 3600000),
        ("b.root-servers.net", 3600000),
        ("c.root-servers.net", 3600000),
        ("d.root-servers.net", 3600000),
        ("e.root-servers.net", 3600000),
        ("f.root-servers.net", 3600000),
        ("g.root-servers.net", 3600000),
        ("h.root-servers.net", 3600000),
        ("i.root-servers.net", 3600000),
        ("j.root-servers.net", 3600000),
        ("k.root-servers.net", 3600000),
        ("l.root-servers.net", 3600000),
        ("m.root-servers.net", 3600000),
    ]
    assert storage.get_record(type_=RTypes.A, record_domain="A.ROOT-SERVERS.NET") == [
        ("198.41.0.4", 3600000)
    ]
