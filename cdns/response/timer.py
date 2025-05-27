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

import time

def _hasher(*args) -> int:
    """
    Hash a bunch of arguments.

    Args:
        *args: Arguments to hash.

    Returns:
        Hash of the arguments.
    """
    h = 0
    for arg in args:
        # Use simple hash method now. In the future, this may be something better
        h += hash(arg)

    return h

class ResourceTimer:
    def __init__(self):
        self.resources = {}

    def start(self, *args):
        self.resources[_hasher(*args)] = time.time()

    def release(self, *args) -> int:
        key = _hasher(*args)

        value = self.resources[key]
        elapsed = time.time() - value
        del self.resources[key]

        return elapsed

    def release_all(self):
        for key in list(self.resources.keys()):
            del self.resources[key]