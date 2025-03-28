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

import functools
import sys
import time
from collections import OrderedDict
from typing import Any, Callable, Hashable, cast

from .protocol import RTypes
from .utils import BiInt

# TODO: Make cache better for storing DNS records, storing the fields rather than a dataclass
# TODO: Merge records and TimedCache into one class


class TimedItem:
    """A singular item that can expire."""

    def __init__(self, item: Any, ttl: int | float) -> None:
        """Create a TimedItem instance.

        Args:
            item: The item.
            ttl: The TTL of the item.
        """
        self.item = item
        self.expiry = time.time() + ttl
        self.ttl = ttl

    def get(self) -> Any:
        """Get the item.

        Returns:
            The item. If it's expired, return None.
        """
        if self.expiry < time.time():
            return None
        return self.item

    def __repr__(self) -> str:
        return f"TimedItem({self.item}, {self.ttl})"

    def __str__(self) -> str:
        return f"TimedItem({self.item}, {self.ttl})"


# TODO: Max length
class DNSCache:
    """A cache for DNS records."""

    def __init__(self) -> None:
        """Create a DNSCache instance."""
        self.data: dict[str, dict[BiInt, list[TimedItem]]] = {}

        self.estimated_size = 0
        """{ "foo.example.com": { "A": [("127.0.0.1", 500)] } }"""

    def _ensure_args(fn: Callable) -> Callable:  # type: ignore
        # YAIMBA
        # Ensure the type of arguments, as well as make necessary fields in self.data.
        # https://stackoverflow.com/a/1263782/21322342
        @functools.wraps(fn)
        def dec_ensure(
            self, name: str, record_type: str | BiInt, *args, **kwargs
        ) -> Any:
            if not isinstance(record_type, BiInt):
                record_type = RTypes[record_type]
            return fn(self, name, record_type, *args, **kwargs)

        return dec_ensure

    def make(self, name: str, record_type: BiInt) -> None:
        if name not in self.data:
            self.data[name] = {}
        if record_type not in self.data[name]:
            self.data[name][record_type] = []

    # TODO: Estimated size
    @_ensure_args
    def add_record(self, name: str, record_type: BiInt, value: str, ttl: int) -> None:
        """Add a singular record to the cache.

        Args:
            name: Domain name.
            record_type: Type of record.
            value: Value of the record.
            ttl: TTL of the record.
        """
        self.make(name, record_type)
        # self.data[name][record_type].append((value, ttl))
        self.data[name][record_type].append(TimedItem(value, ttl))

    @_ensure_args
    def set_record(
        self,
        name: str,
        record_type: BiInt,
        values: list[tuple[str, int]],
        overwrite=False,
    ) -> None:
        """Set multiple records in the cache.

        Args:
            name: Domain name.
            record_type: Type of record.
            values: A list of tuples of a value to a TTL.
            overwrite: Overwrite the existing values. Defaults to False.
        """
        self.make(name, record_type)
        if overwrite:
            self.data[name][record_type] = []
        for data, ttl in values:
            self.add_record(name, record_type, data, ttl)

    @_ensure_args
    def get_records(self, name: str, record_type: BiInt) -> list[tuple[str, int]]:
        """Get the records from the cache.

        Args:
            name: Domain name.
            record_type: Type of record.

        Returns:
            A list containing tuples of a value and a TTL.
        """
        # Do not make. If the record doesn't exist, return nothing
        if self.data.get(name, {}).get(record_type) is None:
            return []

        ret = []
        for item in self.data[name][record_type]:
            value = item.get()
            if value is not None:
                ret.append((value, item.ttl))
        # HACK-TYPING: Why did I think mypy was a good idea -- just look at this mess
        # Just because (int | float) isn't the same as int
        return cast(list[tuple[str, int]], ret)

    def purge(self) -> None:
        """Purge expired records."""
        # For every domain
        for domain in list(self.data.keys()):
            # For every record in every domain
            for record in list(self.data[domain].keys()):
                # Remove all the expired records for the domain
                self.data[domain][record] = [
                    value
                    for value in self.data[domain][record]
                    if value.get() is not None
                ]
                # If the record is empty, delete it
                if not self.data[domain][record]:
                    del self.data[domain][record]

            # If the domain is empty, delete it
            if not self.data[domain]:
                del self.data[domain]
