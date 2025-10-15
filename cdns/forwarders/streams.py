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
import signal
import socket
import threading
from dataclasses import dataclass
from enum import Enum
from typing import cast

from cdns.protocol import *
from cdns.smartselector import get_current_thread_selector

from .base import BaseForwarder


class states:
    """
    Enumeration of different connection states.
    """

    connecting = 0
    sending = 1
    reading_len = 2
    reading_data = 3
    done = 4


@dataclass
class ConnectionContext:
    """
    A dataclass to store information about a connection.
    """

    future: concurrent.futures.Future
    state: states
    out_buf: bytes
    in_len: int
    in_buf: bytes
    addr: tuple[str, int]


class BaseStreamForwarder(BaseForwarder):
    def __init__(self) -> None:
        self.sel = get_current_thread_selector()
        self.lock = threading.Lock()

        self._ctxs: dict[socket.socket, ConnectionContext] = {}

        self.shutdown_event = threading.Event()

        self._thread = threading.Thread(
            target=self._thread_handler
        )  # TODO: Daemon true to false
        self._thread.start()

    def _sigterm_handler(self, stack, frame):
        self.shutdown_event.set()

    def _create_socket(self, addr=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        return sock

    def _register_connection(self, sock, context, events):
        # Use a lock because ctxs is modified here
        with self.lock:
            self._ctxs[sock] = context
            self.sel.register_or_modify(sock, events)

    def _connect(self, sock, addr):
        try:
            sock.connect(addr)
        # This does seem counter-intuitive, but it is necessary. Calling
        # sock.connnect() starts the connection, but it will not finish immediately,
        # because the socket is non-blocking. However, the connection process will
        # start.
        except BlockingIOError:
            pass

    def forward(
        self, query: DNSQuery, addr: tuple[str, int]
    ) -> concurrent.futures.Future[bytes]:
        # Needs to call self._create_socket, self._connect, self._register_connection, and return a future.
        raise NotImplementedError

    def _thread_handler(self):
        while self.sel.is_open and (not self.shutdown_event.is_set()):
            # print("Waiting for events events")
            events = self.sel.safe_select(timeout=1)
            # print("Events received", events)
            for key, mask in events:
                if key.fileobj in self._ctxs.keys():
                    sock = cast(socket.socket, key.fileobj)

                    ctx = self._ctxs.get(sock)
                    if not ctx:
                        # Keep waiting
                        continue

                    try:
                        if mask & selectors.EVENT_READ:
                            self._handle_read(sock, ctx)
                        elif mask & selectors.EVENT_WRITE:
                            self._handle_write(sock, ctx)
                    except Exception as e:
                        logging.debug("error", exc_info=True)
                        ctx.future.set_exception(e)
                        self._cleanup_sock(sock)

    def cleanup(self):
        with self.lock:
            for sock in list(self._ctxs.keys()):
                self._cleanup_sock(sock)

        self.shutdown_event.set()

    def _cleanup_sock(self, sock: socket.socket):
        with self.lock:
            self.sel.unregister(sock)
            self._ctxs.pop(sock, None)  # no error if sock not found
            sock.close()

    def _handle_write(self, sock: socket.socket, ctx: ConnectionContext):
        raise NotImplementedError

    def _handle_read(self, sock: socket.socket, ctx: ConnectionContext):
        raise NotImplementedError
