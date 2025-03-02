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

import functools
import pickle
from pathlib import Path
from typing import Any, Callable

from publicsuffixlist import PublicSuffixList

from .cache import DNSCache
from .protocol import RTypes
from .utils import BiInt
from .zones import DNSZone, parse_zone


class RecordError(Exception):
    """
    An error for a record.
    """

    pass


class RecordStorage:
    """
    A container to store zones and the cache.
    """

    def __init__(self) -> None:
        """
        Create an instance of RecordStorage.
        """
        # Store a TimedCache for upstream requests
        # Lookup zones locally

        self.extractor = PublicSuffixList()

        self.cache = DNSCache()
        self.zones: dict[str, DNSZone] = {}

    def _ensure(fn: Callable) -> Callable:
        # Ensure proper arguments
        @functools.wraps(fn)
        def dec_ensure(self, *args, **kwargs) -> Any:
            if "type_" in kwargs:
                if not isinstance(kwargs["type_"], BiInt):
                    kwargs["type_"] = RTypes[kwargs["type_"]]
            return fn(self, *args, **kwargs)

        return dec_ensure

    @_ensure
    def get_record(
        self,
        *,
        # base_domain: str,
        type_: str,  # RTypes
        record_domain: str,
        record_name: str | None = None,
    ) -> list[tuple[str, int]]:
        """
        Get a record. Prioritize zones over the cache.

        Args:
            type_: Type of record. One of RTypes.
            record_domain: The domain (not apex) for the record.
            record_name: Name of the record (only for SOA). Defaults to None.

        Returns:
            A list of the value of the records to the ttl.
        """
        # Force KWARGS
        # TTL cache wrapper here
        # Record name is used for soa and mx records (exchange)
        # if type_ not in RTypes:
        #    raise RecordError(f"Invalid record type. Given {type_}")

        base_domain = self.extractor.privatesuffix(record_domain)
        values = []
        if base_domain in self.zones:
            # TODO: use ttl here -- can be none
            if type_ == RTypes.SOA:
                values = [getattr(self.zones[base_domain].soa, record_name)]
            elif (
                type_ == RTypes.MX
                and record_domain in self.zones[base_domain].mx_records
            ):
                # Unique exchange
                values = [
                    x
                    for x in self.zones[base_domain].mx_records[record_domain]
                    if x.exchange == record_name
                ]
            else:
                if record_domain in self.zones[base_domain].records:
                    if str(type_) in self.zones[base_domain].records[record_domain]:
                        values = self.zones[base_domain].records[record_domain][
                            str(type_)
                        ]  # This is why BiInt is a terrible idea

        else:
            values = self.cache.get_records(record_domain, type_)

        # TODO: Does wildcard work
        if "*" not in record_domain and len(values) == 0:
            # TODO: Make this faster
            # TODO: Make TTL cache wrapper for function
            return self.get_record(
                type_=type_,
                record_domain=f"*.{base_domain}",  # Wildcard
                record_name=record_name,
            )
        if values is None:
            return []

        return values

    def load_zone_from_file(self, path: Path) -> None:
        """
        Load the zone from a file. The filename must be domain.zone.

        Args:
            path: Path to file.
        """
        # TODO: Support reloading with latest changes
        name, zone = parse_zone(path)
        self.zones[name] = zone

    def load_cache_from_file(self, path: Path) -> None:
        """
        Load the cache from a file.

        Args:
            path: Path to file.
        """
        with open(path, "rb") as f:
            self.cache = pickle.load(f)

    def write_cache_to_file(self, path: Path) -> None:
        """
        Write the cache to a file.

        Args:
            path: Path to file.
        """
        with open(path, "wb") as f:
            pickle.dump(self.cache, f)

    def load_zones_from_dir(self, path: Path) -> None:
        """
        Load all the zones from a directory. Each filename must be domain.zone.

        Args:
            zone_dir_path: Path to directory
        """
        paths = [path / x for x in path.iterdir() if x.suffix == ".zone"]

        for path in paths:
            self.load_zone_from_file(path)

    def __str__(self) -> str:
        return (
            f"RecordStorage(<{len(self.zones)} zones>, <{len(self.cache.data)} cached>)"
        )


if __name__ == "__main__":
    r = RecordStorage()
    r.cache.set("foo", 100, 12)
    r.write_cache_to_file("t.cache")
