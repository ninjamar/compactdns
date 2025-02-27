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


import time
from collections import OrderedDict
from typing import Any, Hashable


# TODO: Make cache better for storing DNS records, storing the fields rather than a dataclass
# TODO: Merge records and TimedCache into one class


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

