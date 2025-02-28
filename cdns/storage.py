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

import os
import pickle
import tldextract  # TODO: Add to requirments
from pathlib import Path
from typing import Literal
from .zones import DNSZone, parse_all_zones, parse_zone
from .cache import DNSCache, TimedCache
from .protocol import RTypes
from .utils import BiInt


class RecordError(Exception):
    pass

class _DummyTC:
    def __init__(self, x):
        self.x = x[0]
        self.ttl = x[1]
    def get(self):
        return self.x
    
def _mk_tc_compat_wrap(x):
    if not isinstance(x, TimedCache):
        return _DummyTC(x)
    return x
class RecordStorage:
    def __init__(self):
        # Store a TimedCache for upstream requests
        # Lookup zones locally
        self.cache = DNSCache()
        self.zones: dict[str, DNSZone] = {}

    def ensure(fn):
        def _ensure(self, *args, **kwargs):
            if "type_" in kwargs:
                if not isinstance(kwargs["type_"], BiInt):
                    kwargs["type_"] = RTypes[kwargs["type_"]]
            return fn(self, *args, **kwargs)

        return _ensure

    @ensure
    def get_record(
        self,
        *,
        # base_domain: str,
        type_: str,  # RTypes
        record_domain: str,
        record_name: str = None,
    ):

        # Force KWARGS
        # TTL cache wrapper here
        # Record name is used for soa and mx records (exchange)
        # if type_ not in RTypes:
        #    raise RecordError(f"Invalid record type. Given {type_}")

        d = tldextract.extract(record_domain)
        base_domain = d.domain + "." + d.suffix
        print("Getting record", type_, record_domain, record_name)

        value = []
        if base_domain in self.zones:
            print("Base domain in self.zones", base_domain)
            if type_ == RTypes.SOA:
                value = [getattr(self.zones[base_domain].soa, record_name)]
            elif (
                type_ == RTypes.MX
                and record_domain in self.zones[base_domain].mx_records
            ):
                # Unique exchange
                value = [
                    x
                    for x in self.zones[base_domain].mx_records[record_domain]
                    if x.exchange == record_name
                ]
            else:
                print(record_domain, self.zones[base_domain].records)
                if record_domain in self.zones[base_domain].records:
                    #print("inside", self.zones[base_domain].records[record_domain])
                    if str(type_) in self.zones[base_domain].records[record_domain]:
                        value = self.zones[base_domain].records[record_domain][str(type_)] # This is why BiInt is a terrible idea
        else:
            value = self.cache.get_records(record_domain, type_)
            # Store the
            # return self.cache.get()
        # TODO: BROKEN
        if "*" not in record_domain and (value is None or len(value) == 0):
            # TODO: Make this faster
            # TODO: Make TTL cache wrapper for function
            return self.get_record(
                type_=type_,
                record_domain=f"*.{base_domain}",  # Wildcard
                record_name=record_name,
            )
        if value is None:
            return None
        
        return [_mk_tc_compat_wrap(x) for x in value]

    def load_zone_from_file(self, path: Path):
        # TODO: Support reloading with latest changes
        name, zone = parse_zone(path)
        self.zones[name] = zone

    def load_cache_from_file(self, path: Path):
        with open(path, "rb") as f:
            self.cache = pickle.load(f)

    def write_cache_to_file(self, path: Path):
        with open(path, "wb") as f:
            pickle.dump(self.cache, f)

    def load_zones_from_dir(self, zone_dir_path: Path):
        zone_paths = [
            zone_dir_path / x for x in zone_dir_path.iterdir() if x.suffix == ".zone"
        ]

        for path in zone_paths:
            self.load_zone_from_file(path)

    def __str__(self):
        return (
            f"RecordStorage(<{len(self.zones)} zones>, <{len(self.cache.data)} cached>)"
        )


if __name__ == "__main__":
    r = RecordStorage()
    r.cache.set("foo", 100, 12)
    r.write_cache_to_file("t.cache")
