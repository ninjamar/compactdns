# compactdns
# A simple forwarding DNS server with blocking capabilities
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


import dataclasses
import io
import re
from pathlib import Path


@dataclasses.dataclass
class SOARecord:
    """Start of Authority (SOA) Record"""

    # https://www.cloudflare.com/learning/dns/dns-records/dns-soa-record/
    primary_ns: str
    admin_email: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclasses.dataclass
class MXRecord:
    """Mail Exchange (MX) Record"""

    # https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/
    priority: int
    exchange: str


@dataclasses.dataclass
class DNSZone:
    """DNS Zone"""

    domain: str
    ttl: int = 3600
    soa: SOARecord | None = None
    mx_records: dict[str, list[MXRecord]] = dataclasses.field(default_factory=dict)

    records: dict[str, dict[str, list[(str, int)]]] = dataclasses.field(
        default_factory=dict
    )  # default value

    def add_record(
        self, name: str, record_type: str, value: str, ttl: int | None = None
    ) -> None:
        """
        Add a record.

        Args:
            name: Name of the record.
            record_type: Type of the record (eg A, TXT, MX).
            value: Value of the record.
        """
        if not ttl:
            ttl = self.ttl

        if name.endswith("."):
            name = name[:-1]
        if record_type == "MX":
            priority, exchange = value.split(maxsplit=1)  # split by whitespace once
            if name not in self.mx_records:
                self.mx_records[name] = []
            self.mx_records[name].append(MXRecord(int(priority), exchange))
        else:
            if name not in self.records:
                self.records[name] = {}
            if record_type not in self.records[name]:
                self.records[name][record_type] = []

            self.records[name][record_type].append((value, ttl))


class Records:
    pass


"""
DNSZone(
    domain="example.com",
    ttl=3600,
    soa=SOARecord(
        primary_ns="ns1.example.com",
        admin_email="admin.example.com",  # admin@example.com
        serial=1234567890,
        refresh=3600,  # ttl
        retry=1800,
        expire=604800,
        minimum=86400,
    ),
    mx_records={
        "example.com": [
            MXRecord(priority=10, exchange="mail.example.com"),
            MXRecord(priority=20, exchange="backup-mail.example.com"),
        ]
    },
    records={"example.com": {"A": [("96.7.128.198", 4600)]}},
)
"""


class ZoneParsingError(Exception):
    pass


class ZoneParser:
    def __init__(self, domain: str, stream: io.TextIOWrapper) -> None:
        self.stream = stream
        self.zone = DNSZone(domain=domain)
        self.line = None

    def parse_instr(self) -> None:
        if self.line[0] == "$":
            matches = re.match(r"^\$(.*) (.*)$", self.line).groups()
            if matches[0] == "ORIGIN":
                self.zone.domain = matches[1]
            elif matches[0] == "TTL":
                self.zone.ttl = int(matches[1])
            elif matches[0] == "INCLUDE":
                pass
            elif matches[0] == "GENERATE":
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
        record_type = None
        value = None

        temp = ""
        in_quotes = False
        parts = []
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

        name = parts[0]
        if all(x.isdigit() for x in parts[1]):  # tt;
            ttl = int(parts[1])
            # "IN" is inbetween name and record_type
            record_type = parts[3]
            value = " ".join(parts[4:])  # if len(parts) > 4 else None
        else:
            record_type = parts[2]
            value = " ".join(parts[3:])  # if len(parts) > 2 else None

        self.zone.add_record(name, record_type, value, ttl)

    def parse(self) -> None:
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
        self.line = self.stream.readline()
        if not self.line:
            raise ZoneParsingError("Unable to parse")
        self.line = self.line.strip().split(";")[0].strip()


def parse_zone(path: Path) -> DNSZone:
    # name = path.split("/")[-1][:-5]  # Filename, then extract domain.zone
    name = path.stem
    with open(path) as f:
        p = ZoneParser(name, f)
        p.parse()
        return name, p.zone


def parse_all_zones(paths: list[str]) -> dict[str, DNSZone]:
    zones: dict[str, DNSZone] = {}
    for path in paths:
        name, zone = parse_zone(path)
        zones[name] = zone
    return zones


if __name__ == "__main__":
    path = "/".join(__file__.split("/")[:-2]) + "/example-zones/example.com.zone"
    zones = parse_all_zones([path])
    print(zones)
