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

import concurrent.futures
import selectors
import socket
import ssl
import threading
import struct
from typing import cast
from collections import namedtuple
from enum import Enum


from cdns.protocol import (
    DNSAdditional,
    DNSAnswer,
    DNSAuthority,
    DNSHeader,
    DNSQuery,
    DNSQuestion,
    RTypes,
    auto_decode_label,
    get_ip_mode_from_rtype,
    get_rtype_from_ip_mode,
    unpack_all,
)
from .base import BaseResolver
from cdns.resolver import forwarders

class UpstreamResolver(BaseResolver):
    """A class to resolve from upstream."""

    def __init__(self, addr: tuple[str, int]) -> None:
        """Create an instance of UpstreamResolver.

        Args:
            addr: Address of the upstream.
        """
        self.addr = addr
        self.forwarder = forwarders.UdpForwarder()

    def send(self, query: DNSQuery) -> concurrent.futures.Future[DNSQuery]:
        """Send a query to the upstream.

        Args:
            query: Query to send.

        Returns:
            The future fufilling the query.
        """
        ret: concurrent.futures.Future[DNSQuery] = concurrent.futures.Future()

        f = self.forwarder.forward(query, self.addr)
        f.add_done_callback(
            lambda s: ret.set_result(unpack_all(s.result()))
        )  # ret.result = unpack_all(s.result)

        return ret

    def cleanup(self):
        self.forwarder.cleanup()