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
import struct
import threading
from collections import namedtuple
from enum import Enum
from typing import cast

from cdns.protocol import (DNSAdditional, DNSAnswer, DNSAuthority, DNSHeader,
                           DNSQuery, DNSQuestion, RTypes, auto_decode_label,
                           get_ip_mode_from_rtype, get_rtype_from_ip_mode,
                           unpack_all)

from .base import BaseForwarder


class UdpForwarder(BaseForwarder):
    """Forwarder using UDP."""

    def __init__(self) -> None:
        """Create an instance of UDPForwarder."""

        # When we want to send, send the request, and add the socket to
        # pending_requests and selectors. When the socket can be read (checked)
        # in the thread, fufil the future.

        self.sel = selectors.DefaultSelector()
        self.pending_requests: dict[socket.socket, concurrent.futures.Future] = {}

        self.lock = threading.Lock()

        self.thread = threading.Thread(
            target=self._thread_handler
        )  # TODO: Daemon true or false
        self.thread.daemon = True
        self.thread.start()

    def _thread_handler(self) -> None:
        """Handler for the thread that handles the response for forwarded
        queries."""

        # TODO: Add a way to use TLS for forwarding (use_secure_forwarder=True)

        while True:
            events = self.sel.select(timeout=1)  # TODO: Timeout
            with self.lock:  # TODO: Lock here?
                for key, mask in events:
                    # TODO: Try except
                    sock = cast(socket.socket, key.fileobj)
                    # Don't error if no key
                    future = self.pending_requests.pop(sock, None)
                    if future:
                        try:
                            # TODO: Support responses larger longer than 512 using TCP
                            response, _ = sock.recvfrom(512)
                            future.set_result(response)
                        except Exception as e:
                            future.set_exception(e)
                        finally:
                            self.sel.unregister(sock)
                            sock.close()

    def forward(
        self, query: DNSQuery, addr: tuple[str, int]
    ) -> concurrent.futures.Future[bytes]:
        """Forward a DNS query to an address.

        Args:
            query: The DNS query to forward.
            addr: Address of the server.

        Returns:
            The response from the forwarding server.
        """
        # TODO: If using TCP, use a different socket (can be same, even though overhead -- much less tcp requests)
        # TODO: If TC, use either TLS or UDP with multiple packets
        # TODO: TC flag?

        # new socket for each request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        future: concurrent.futures.Future = concurrent.futures.Future()

        # TODO: The bottleneck
        try:
            sock.sendto(query.pack(), addr)
            with self.lock:
                # Add a selector, and when it is ready, read from pending_requests
                self.sel.register(sock, selectors.EVENT_READ)
                self.pending_requests[sock] = future

        except Exception as e:
            future.set_exception(e)
            sock.close()
        return future

    def cleanup(self):
        for sock in self.pending_requests.keys():
            sock.close()
