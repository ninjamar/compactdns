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
import logging
import selectors
import socket
import ssl
import struct
import threading
from collections import namedtuple
from enum import Enum
from typing import cast

import h2.config
import h2.connection
import h2.events

from cdns.protocol import *
from cdns.smartselector import get_current_thread_selector

from ..base import BaseForwarder


class HttpTwoForwarder(BaseForwarder):

    def __init__(self, use_tls=True):
        if not use_tls:
            logging.warning("Not using TLS for DoH endpoint")

        self.sel = get_current_thread_selector()
        self.pending_requests: dict[
            socket.socket, tuple[concurrent.futures.Future, h2.connection.H2Connection]
        ] = {}

        self.use_tls = use_tls

        self.lock = threading.Lock()

        self.shutdown_event = threading.Event()

        self.thread = threading.Thread(
            target=self._thread_handler,
        )  # TODO: Daemon true or false
        self.thread.start()

        # Architecture:
        # Make the request in self.forward
        # Get response in self._thread_handler

    def _thread_handler(self):
        while self.sel.is_open and (not self.shutdown_event.is_set()):
            events = self.sel.safe_select(timeout=1)  # TODO: Timeout
            with self.lock:  # TODO: Lock here?
                for key, mask in events:
                    if key.fileobj in self.pending_requests.keys():
                        sock = cast(socket.socket, key.fileobj)
                        # Don't error if no key
                        # future = self.pending_requests.pop(sock, None)
                        future = self.pending_requests.get(sock)

                        if mask & selectors.EVENT_READ:
                            # Read data from socket

                            data = sock.recv(4096)
                            if not data:
                                break

    def forward(
        self,
        query: DNSQuery,
        addr: tuple[str, int],
        host: str,
        path: str = "/dns-query",
    ) -> concurrent.futures.Future[bytes]:

        # TODO: Resolve host using DNS. This might require me creating a public API.
        future: concurrent.futures.Future[bytes] = concurrent.futures.Future()
        try:

            to_send = query.pack()

            sock = socket.create_connection(addr)

            if self.use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.set_alpn_protocols(["h2"])

                sock = ssl_ctx.wrap_socket(sock)

            conn = h2.connection.H2Connection()
            conn.initiate_connection()

            sock.sendall(conn.data_to_send())

            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(
                stream_id,
                [
                    (":method", "GET"),
                    (":authority", host),
                    (":scheme", "https"),
                    (":path", path),
                ],
                end_stream=True,
            )

            sock.sendall(conn.data_to_send())
        except Exception as e:
            future.set_exception(e)
        return future

    def cleanup(self):
        with self.lock:
            for sock in self.pending_requests.keys():  # explicit
                sock.close()

        self.shutdown_event.set()
