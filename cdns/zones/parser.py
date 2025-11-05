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
# SOFTWARE.

# This is needed to prevent an error for self referencing a class in an annotation
# item: "ZoneCollection" | DNSZone

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Literal

from .zone import *

__all__ = [
    "parse_directory",
    "parse_file",
    "parse_contents",
    "DNSZone",
    "ZoneCollection",
    "FORMAT",
]

FORMAT = Literal["zone", "root", "json"]


class ZoneParsingError(Exception):
    """An error while parsing a zone."""

    pass


class ZoneParser:
    """A class to parse a DNS zone from a zone file."""

    def __init__(self, domain: str, stream: io.TextIOWrapper) -> None:
        """Create an instance of ZoneParser.

        Args:
            domain: The base domain for the zone file.
            stream: Stream for the zone.
        """
        self.stream = stream
        self.zone = DNSZone(domain=domain)
        self.line: str | None = None

    def parse_instr(self) -> None:
        """Parse a section in the zone file.

        Raises:
            ZoneParsingError: Unable to parse zone.
            ZoneParsingError: Incomplete SOA.
        """
        if not self.line:
            return
        # TODO: This has a mccabe complexity of 17
        if self.line[0] == "$":
            matches = re.match(r"^\$(.*) (.*)$", self.line)
            if matches is None:
                raise ZoneParsingError()

            groups = matches.groups()

            if groups[0] == "ORIGIN":
                self.zone.domain = groups[1]
            elif groups[0] == "TTL":
                self.zone.ttl = int(groups[1])
            elif groups[0] == "INCLUDE":
                # TODO: Support
                pass
            elif groups[0] == "GENERATE":
                # TODO: Support
                pass
            else:
                raise ZoneParsingError("Unable to parse zone", self.line)
            return

        if "SOA" in self.line:
            # The zonefile format isn't always enforced
            domain, _, _1, primary_ns, admin_email, *rest = (
                self.line.split()
            )  # _ = IN, _1 = SOA, rest = every thing else

            fields = []
            for i in range(5):  # serial, refresh, retry, expire, minimum (ttl)
                self.fetch()
                if not self.line:
                    # TODO: Doesn't work because self.fetch already raises an error
                    raise ZoneParsingError("Incomplete SOA")
                fields.append(int(self.line))

            self.zone.soa = SOARecord(
                primary_ns=primary_ns,
                admin_email=admin_email,
                serial=fields[0],
                refresh=fields[1],
                retry=fields[2],
                expire=fields[3],
                minimum=fields[4],
            )

            self.fetch()  # Closing parenthecies
            return

        name = None
        ttl = None
        record_class = None
        record_type = None
        rdata = None

        temp = ""
        in_quotes = False
        parts: list[str] = []
        # name, ttl (optional), _in, record_type, value

        for i, char in enumerate(self.line):
            if char == '"' and in_quotes:
                in_quotes = False
                parts.append(temp)
                temp = ""
            elif char == '"' and not in_quotes:
                in_quotes = True
                temp = ""
            elif char == " " and not in_quotes:
                if temp:
                    parts.append(temp)
                    temp = ""
            else:
                temp += char

        if temp:
            parts.append(temp)

        # Parts: name [ttl] [class] type rdata
        # Things in brackets are optional

        # name -- normalized in self.zone.add_record
        name = parts[0]

        i = 1

        # ttl, optional
        if parts[i].isdigit():
            ttl = int(parts[i])
            i += 1
        else:
            ttl = None
        # class, optional
        if parts[i].upper() in {"IN", "CH", "HS"}:
            record_class = parts[i].upper()
            i += 1
        else:
            record_class = "IN"  # default

        # type
        record_type = parts[i].upper()

        i += 1
        rdata = " ".join(parts[i:]) if i < len(parts) else ""

        if record_class != "IN":
            raise Exception("Unable to support non-Internet classes")

        self.zone.add_record(name, record_type, rdata, ttl)

    def parse(self) -> None:
        """Parse the entire stream into the zone."""
        # I mean I could use regex's but I already started this
        # https://regex101.com/r/7yNlJu/1

        self.line = None
        while True:
            # self.line = self.stream.readline()
            self.line = self.stream.readline()
            if not self.line:
                break
            self.line = self.line.strip().split(";")[0].strip()
            if self.line != "":
                self.parse_instr()

    def fetch(self) -> None:
        """Fetch a expected line from the stream.

        Raises:
            ZoneParsingError: If the zone cannot be parsed.
        """
        # TODO: Remove this function
        self.line = self.stream.readline()
        if not self.line:
            raise ZoneParsingError("Unable to parse")
        # Remove comments and extra whitespace
        self.line = self.line.strip().split(";")[0].strip()


def dict_to_zone(j: dict) -> DNSZone:
    """Parse a singular zone from json.

    Args:
        j: The json.

    Returns:
        The DNS zone.
    """
    zone = DNSZone(domain=j["domain"])
    if "ttl" in j:
        zone.ttl = int(j["ttl"])
    if "soa" in j:
        soa = j["soa"]
        zone.soa = SOARecord(
            primary_ns=soa["primary_ns"],
            admin_email=soa["admin_email"],
            serial=int(soa["serial"]),
            refresh=int(soa["refresh"]),
            retry=int(soa["retry"]),
            expire=int(soa["expire"]),
            minimum=int(soa["minimum"]),
        )
    if "mx_records" in j:
        for domain in j["mx_records"]:
            zone.mx_records[domain] = [
                MXRecord(int(x["priority"]), x["exchange"])
                for x in j["mx_records"][domain]
            ]

    for domain in j["records"]:
        for type_ in j["records"][domain]:
            for v in j["records"][domain][type_]:
                if len(v) == 1:
                    zone.add_record(domain, type_, v[0])
                else:
                    zone.add_record(domain, type_, v[0], int(v[1]))
    return zone


class ZoneCollection(dict):
    # def __init__(self):
    #    self.zones: dict[str, DNSZone] = {}

    def update_zones(self, item: "ZoneCollection" | DNSZone):
        if isinstance(item, DNSZone):
            if item.domain in self:
                self[item.domain].update_from(item)
            else:
                self[item.domain] = item

        elif isinstance(item, ZoneCollection):
            for zone in item.items():
                self.update_zones(zone)


def detect_format_by_ext(path: Path) -> FORMAT:
    # Only check the last suffix because domain is the first part
    if path.suffix == ".zone":
        return "zone"

    if path.suffix == ".root":
        return "root"

    if path.suffix == ".json":
        return "json"

    raise ValueError("Invalid path")


def detect_format(path: Path) -> FORMAT:
    return detect_format_by_ext(path)


"""
IF A ZONE EXISTS IN MULTIPLE FILES USE DNSZone.update_from
Valid Zone Formats (in order of hierarchy) -- (this means it will be loaded in reverse order):
- .zone
- .root
- .json
- .all.json
"""


def parse_directory(path: Path) -> ZoneCollection:
    zc = ZoneCollection()

    # Need to sort this by file ext to respect hierarchy
    for file_path in path.iterdir():
        zone = parse_file(file_path)

        zc.update_zones(zone)
    return zc


def parse_file(path: Path, zone_domain: str | None = None) -> DNSZone:
    with open(path) as f:
        return parse_contents(
            f.read(),
            detect_format(path),
            zone_domain=path.stem if zone_domain is None else zone_domain,
        )


def parse_contents(
    data: str, format: FORMAT, zone_domain: str | None = None
) -> DNSZone | ZoneCollection:
    # print(data)
    if format == "zone":
        stream = io.StringIO(data)
        parser = ZoneParser(zone_domain, stream)
        parser.parse()

        return parser.zone

    if format == "root":
        stream = io.StringIO(data)
        parser = ZoneParser("", stream)
        parser.parse()

        return parser.zone

    if format == "json":
        data = json.loads(data)
        if isinstance(data, list):
            zc = ZoneCollection()

            for zone_dict in data:
                zone = dict_to_zone(zone_dict)
                zc.update_zones(zone)

            return zc
        else:
            return dict_to_zone(data)


if __name__ == "__main__":
    from cdns.server.storage import RecordStorage

    storage = RecordStorage()

    zone = parse_file(Path("ignore/named.root"), zone_domain=".")
    print(zone)
    storage.zones = [zone]

    storage.get_record(type_="A")
