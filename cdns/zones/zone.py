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


import dataclasses
from cdns.protocol import RTypes


def normalize_name(name: str, zone_domain: str | None = None) -> str:
    if not name or name == "@":
        return (zone_domain or "").lower()

    if name == ".":  # canocal root
        return ""

    is_absolute = name.endswith(".")  # abs means fqdn
    if is_absolute:
        name = name[:-1]

    if zone_domain and not is_absolute:  # only add if relative
        return f"{name}.{zone_domain}".lower()
    return name.lower()


@dataclasses.dataclass
class SOARecord:
    """Start of Authority (SOA) Record."""

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
    """Mail Exchange (MX) Record."""

    # https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/
    priority: int
    exchange: str


@dataclasses.dataclass
class DNSZone:
    """DNS Zone dataclass."""

    domain: str
    ttl: int = 3600
    soa: SOARecord | None = None
    mx_records: dict[str, list[MXRecord]] = dataclasses.field(default_factory=dict)

    records: dict[str, dict[str, list[tuple[str, int]]]] = dataclasses.field(
        default_factory=dict
    )  # default value

    def add_record(
        self, name: str, record_type: str, value: str, ttl: int | None = None
    ) -> None:
        """Add a record to the zone.

        Args:
            name: Name of the record.
            record_type: Type of the record (eg A, TXT, MX).
            value: Value of the record.
            ttl: Time to live for record.
        """
        if not ttl:
            ttl = self.ttl

        # if name.endswith("."):
        #    name = name[:-1]
        # if "." not in name:
        #    name = name + "." + self.domain
        name = normalize_name(name, self.domain)

        if record_type == "MX":
            priority, exchange = value.split(maxsplit=1)  # split by whitespace once

            exchange = normalize_name(exchange, self.domain)

            if name not in self.mx_records:
                self.mx_records[name] = []
            self.mx_records[name].append(MXRecord(int(priority), exchange))
        else:
            if name not in self.records:
                self.records[name] = {}
            if record_type not in self.records[name]:
                self.records[name][record_type] = []

            if record_type in {RTypes.CNAME, RTypes.NS}:
                value = normalize_name(value, self.domain)

            self.records[name][record_type].append((value, ttl))

    def update_from(self, other: "DNSZone") -> None:
        # Update self with values from other.
        # Make sure to do this recurisvely
        if not isinstance(other, DNSZone):
            raise ValueError("other must be an instance of DNSZone")

        if other.soa is not None:
            self.soa = other.soa

        if other.ttl is not None:
            self.ttl = other.ttl

        for name, mx_records in other.mx_records.items():
            if name not in self.mx_records:
                self.mx_records[name] = []
            # Merge self to other
            for mx_record in other.mx_records[name]:
                if mx_record not in self.mx_records[name]:
                    self.mx_records[name].append(mx_record)

        for name, record_type_pair in other.records.items():
            if name not in self.records:
                self.records[name] = {}

            for record_type, values in record_type_pair.items():
                if record_type not in self.records[name]:
                    self.records[name][record_type] = []

                for ip, ttl in values:
                    if not any(
                        ip == stuff[0] for stuff in self.records[name][record_type]
                    ):
                        # if value not in self.records[name][record_type]:
                        self.records[name][record_type].append((ip, ttl))


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
