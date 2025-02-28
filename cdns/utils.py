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
    def __init__(self, a, b):
        if isinstance(a, int):
            self.i = a
            self.s = b
        else:
            self.i = b
            self.s = a

    """
    def __eq__(self, x):
        # print(dir(self))
        if isinstance(x, BiInt):
            # print(type(x.i), type(x.s))
            return x.i == self.i and x.s == self.s
        if isinstance(x, int):
            return self.i == x
        if isinstance(x, str):
            return self.s == x
        return False
        # return x == self.i or x == self.s

    def __str__(self):
        return self.s
    
    def __hash__(self):
        return hash((self.i, self.s))"
    """

    def __str__(self):
        return self.s
    def __int__(self):
        return self.i

    def __eq__(self, x):
        if isinstance(x, BiInt):
            return str(self) == str(x)
        return False

    def __hash__(self):
        return hash(self.__str__())

    def __repr__(self):
        return self.__str__()


if __name__ == "__main__":
    a = BiInt("hello", 1)
    print("hello" == a)


class ImmutableBiDict:
    def __init__(self, values: list[tuple[Any, Any]]):
        self.data = {}

        for value in values:
            self.data[value[0]] = value[1]
            self.data[value[1]] = value[0]

    def __contains__(self, a):
        return a in self.data

    def __getitem__(self, x):
        a = self.data[x]
        b = self.data[a]
        return BiInt(a, b)

    # TODO: Make immutable
    def __getattr__(self, x):
        return self.__getitem__(x)
