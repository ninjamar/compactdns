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

import concurrent.futures

from cdns import forwarders
from cdns.protocol import *
from cdns.resolvers.base import METHOD

"""
This is different from the server and server.response.

The client is responsible for taking a DNSQuery object, sending it (via a forwarder)
and returning the resulting future.
"""

FORWARDERS = {
    "doh": forwarders.HTTPForwarder,
    "tcp": forwarders.TCPForwarder,
    "tls": forwarders.TLSForwarder,
    "udp": forwarders.UDPForwarder,
}


class Client:
    def __init__(
        self,
    ):
        self.forwarders_map: dict[str, forwarders.BaseForwarder] = {
            k: v() for k, v in FORWARDERS.items()
        }

    def resolve(
        self,
        query: DNSQuery,
        method: METHOD,
        addr: tuple[str, int] = None,
    ) -> concurrent.futures.Future[DNSAnswer]:
        return_future: concurrent.futures.Future[DNSAnswer] = (
            concurrent.futures.Future()
        )

        future = self.forwarders_map.get(method).forward(query, addr)

        def unpack_query(f: concurrent.futures.Future[bytes]):
            data = f.result()
            unpacked = unpack_all(data)
            return_future.set_result(unpacked)

        future.add_done_callback(unpack_query)
        return return_future

    def cleanup(self):
        """Cleanup any loose ends."""
        for forwarder in self.forwarders_map.values():
            forwarder.cleanup()
