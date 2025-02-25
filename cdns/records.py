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


"""
The usage of "records" means DNS records...
"""

import fnmatch
import json
import os.path
import time
import tomllib
from collections import OrderedDict
from collections.abc import KeysView
from typing import Any, Hashable, NamedTuple

FNMATCH_CHARS = "*?[]!"


class TimedCache:
    """A dictionary, with expiring keys."""

    def __init__(self, max_length: int = float("inf")) -> None:  # type: ignore
        """Create a TimedCache instance."""
        self.data: OrderedDict[Hashable, tuple[Any, float, float]] = OrderedDict()
        self.max_length = max_length

    def set(self, key: Hashable, value: Any, ttl: float) -> None:
        """Set a key in the TimedCache.

        Args:
            key: The key to set.
            value: The value of the key.
            ttl: The time to expiry of the key in the future.
        """
        # If the item already exists, move it to the end
        if key in self.data:
            self.data.move_to_end(key)

        if len(self.data) >= self.max_length:
            # Pare down size
            self.data.popitem(last=False)

        self.data[key] = (value, time.time() + ttl, ttl)

    def get(self, key: Hashable) -> Any:
        """Get a timed key, deleting it if it has expired.

        Args:
            key: The key to get.

        Returns:
            The value of the key.
        """
        if key not in self.data:
            return None

        value, expiry, _ = self.data[key]

        # Remove the item if it's expired
        if expiry < time.time():
            del self.data[key]
            return None
        return value

    def renew_ttl(self, key: Hashable) -> None:
        """Renew the TTL for a key.

        Args:
            key: The key to renew the TTL.
        """
        self.set(key, self.get(key), self.data[key][2])

    def get_and_renew_ttl(self, key: Hashable) -> Any:
        """Get a key and renew it's TTL.

        Args:
            key: The key to get and renew it's TTL.

        Returns:
            The value of the key.
        """
        value = self.get(key)
        self.set(key, value, self.data[key][2])
        return value

    def __contains__(self, key: Hashable) -> bool:
        """Check if the TimedCache contains a key.

        Args:
            key: The key to check.

        Returns:
            Is the key inside the TimedCache?
        """
        return self.get(key) is not None


class RecordsItem(NamedTuple):
    """IP address and ttl for a host."""

    ip: str
    ttl: float


class Records:
    """A class to store records."""

    def __init__(
        self,
        normal_records: dict[str, RecordsItem],
        fnmatch_records: dict[str, RecordsItem],
    ) -> None:
        """Create an instance of Records.

        Args:
            normal_records: Records using host to ip address syntax.
            fnmatch_records: Records using host to IP address syntax
            where host supports fnmatch syntax.
        """
        self.normal = normal_records
        self.fnmatch = fnmatch_records

    def lookup(self, name: str) -> str | None:
        """Find the match for a name in the records.

        Args:
            name: The name to find the match.

        Returns:
            The match for the name.
        """
        if name in self.normal:
            return name
        if ret := next(
            (loc for loc in self.fnmatch.keys() if fnmatch.fnmatch(name, loc)),
            None,
        ):
            return ret
        return None

    def __getitem__(self, item: str) -> RecordsItem:
        """Get an item from the records.

        Args:
            item: The item to get.

        Raises:
            KeyError: If the item isn't found.

        Returns:
            The value of the item.
        """
        if item in self.normal:
            return self.normal[item]
        if item in self.fnmatch:
            return self.fnmatch[item]
        raise KeyError(item)

    def keys(self) -> KeysView:
        """Get all the keys in the records..

        Returns:
            All the keys in the records..
        """
        return (self.normal | self.fnmatch).keys()

    def __repr__(self) -> str:
        """Repr format of Records.

        Returns:
            Repr format of Records.
        """
        return f"Records(<{len(self.normal)} normal rules>, <{len(self.fnmatch)} fnmatch rules>)"

    def __len__(self) -> int:
        return len(self.normal) + len(self.fnmatch)


def is_fnmatch_host(host: str) -> bool:
    """Check if a host uses fnmatch syntax.

    Args:
        host: The host to check.

    Returns:
        Does the host use fnmatch syntax?
    """ """"""
    return any(x in host for x in FNMATCH_CHARS)


# I don't know how to get mypt to accept data: dict | list[bytes] so I set it to any instead
def parse_records(
    data: Any, master_ttl: int
) -> tuple[dict[str, RecordsItem], dict[str, RecordsItem]]:
    """Parse the records.

    Args:
        data: The records to parse.
        master_ttl: Master TTL if TTL isn't set.

    Returns:
        One dictionary of hosts to IP addresses, another dictionary of hosts
        using fnmatch syntax to IP addresses.
    """

    # TODO: Validate ip
    # TODO: Check for collision
    normal_records = {}
    fnmatch_records = {}

    # Hosts format
    if isinstance(data, list):
        for line in data:
            line = line.decode()
            if not line.startswith("#"):
                ip, host = line.strip().split()
                item = RecordsItem(ip=ip, ttl=master_ttl)
                if is_fnmatch_host(host):
                    fnmatch_records[host] = item
                else:
                    normal_records[host] = item
    else:
        # Normal format
        ttl = data.get("ttl", master_ttl)
        for host, target_ip in data.get("target-list", {}).items():
            item = RecordsItem(ip=target_ip, ttl=ttl)
            if is_fnmatch_host(host):
                fnmatch_records[host] = item
            else:
                normal_records[host] = item

        for rule in data.get("rules", []):
            target_ip = rule["target_ip"]
            rule_ttl = rule.get("ttl", ttl)
            for host in rule["hosts"]:
                item = RecordsItem(ip=target_ip, ttl=rule_ttl)
                if is_fnmatch_host(host):
                    fnmatch_records[host] = item
                else:
                    normal_records[host] = item

    # FIXME: Explicit return tuple?
    return normal_records, fnmatch_records


def read_records(
    fpath: str, master_ttl: int
) -> tuple[dict[str, RecordsItem], dict[str, RecordsItem]]:
    """Read and parse records from a file.

    Args:
        fpath: The path to the file.
        master_ttl: Master TTL if TTL isn't set.

    Raises:
        Exception: Unknown file extension.

    Returns:
        The parsed records.
    """
    with open(fpath, "rb") as f:
        ext = os.path.splitext(fpath)[1]
        if ext == ".json":
            return parse_records(json.load(f), master_ttl)
        elif ext == ".toml":
            return parse_records(tomllib.load(f), master_ttl)
        else:
            return parse_records(f.readlines(), master_ttl)


def load_all_records(paths: list[str], master_ttl: int) -> Records:
    """Load all records from a list of paths.

    Args:
        paths: A list containing paths to the records.
        master_ttl: Master TTL if TTL isn't set.


    Returns:
        The records from those files.
    """
    normal_records = {}
    fnmatch_records = {}
    for path in paths:
        normal_b, fnmatch_b = read_records(path, master_ttl)
        normal_records.update(normal_b)
        fnmatch_records.update(fnmatch_b)
    return Records(normal_records, fnmatch_records)
