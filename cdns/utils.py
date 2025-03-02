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
import socket
from typing import Any


@functools.cache
def is_ip_addr_valid(ip_addr: str) -> bool:
    """Check if an IP address is valid. This function caches the validity of an
    IP address.

    Args:
        ip_addr: The IP address to check validity.

    Returns:
        Is the IP address valid?
    """
    try:
        socket.inet_aton(ip_addr)
        return True
    except socket.error:
        return False


# TODO: Don't use this class. Just use strings instead. Actual waste of time.
# TODO: Should actually be BiInt
# TODO: This is too overcomplicated
class BiInt:
    """
    A container for an something that can be both an integer and a string.
    """

    def __init__(self, a: str | int, b: str | int) -> None:
        """
        Create an instance of BiInt.

        Args:
            a: str or int.
            b: str or int.

        One of `a` and `b` has to be a string, while the other one has to be an int.
        """
        if isinstance(a, int):
            self.i = a
            self.s = b
        else:
            self.i = b
            self.s = a

    def __str__(self) -> str:
        return str(self.s)

    def __int__(self) -> int:
        return self.i

    def __eq__(self, x) -> bool:
        if isinstance(x, BiInt):
            return str(self) == str(x)
        return False

    def __hash__(self) -> int:
        return hash(self.__str__())

    def __repr__(self) -> str:
        return self.__str__()


class ImmutableBiDict:
    """
    An immutable dictionary with forward and backward keys.
    """

    def __init__(self, values: list[tuple[Any, Any]]):
        """
        Create an instance of ImmutableBiDict.

        Args:
            values: A list of values with the items.
        """
        self.data = {}

        for value in values:
            self.data[value[0]] = value[1]
            self.data[value[1]] = value[0]

    def __contains__(self, a):
        return a in self.data

    def __getitem__(self, x):
        # HACK: Use .get so we don't get an error for wrong ones
        a = self.data.get(x, 0)
        b = self.data.get(a, "")

        return BiInt(a, b)

    # TODO: Make immutable
    def __getattr__(self, x):
        return self.__getitem__(x)


if __name__ == "__main__":
    a = BiInt("hello", 1)
    print("hello" == a)
