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
from dataclasses import dataclass
from enum import Enum
from typing import cast

import h11

from cdns.protocol import *
from cdns.smartselector import get_current_thread_selector

from ..base import BaseForwarder


class states:
    ssl_handshake = 0

    connecting = 1
    h11_process = 2
    cleanup = 3


@dataclass
class ConnectionContext:
    """
    A dataclass to store information about a connection.
    """

    future: concurrent.futures.Future
    state: states
    h1conn: h11.Connection | None
    buf: bytes | None


class HttpOneForwarder(BaseForwarder):
    def __init__(self, use_tls=True):
        if not use_tls:
            logging.warning("Not using TLS for DoH endpoint")

        self.sel = get_current_thread_selector()
        self.pending_requests: dict[socket.socket, ConnectionContext] = {}

        self.use_tls = use_tls

        self.lock = threading.Lock()

        self.shutdown_event = threading.Event()

        self.thread = threading.Thread(
            target=self._thread_handler
        )  # TODO: Daemon true or false
        self.thread.start()

    def handle_state(self, sock: ssl.SSLContext, ctx: ConnectionContext):
        # Returns true if we need to continue
        if ctx.state == states.ssl_handshake:
            try:
                sock.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return

            self.sel.modify(sock, selectors.EVENT_READ)
            ctx.state = states.connecting
            return

        elif ctx.state == states.connecting:
            # Connect to socket by recieving data and making a h11.Connection

            # Should hopefully allow for smoother operation by receiving less data
            if ctx.h1conn is not None or ctx.buf is not None:
                raise Exception("ctx.h1conn and ctx.buf both need to be None")

            ctx.h1conn = h11.Connection(h11.CLIENT)
            ctx.state = states.h11_process

            ctx.buf = b""

            self.sel.modify(sock, selectors.EVENT_READ)
            return
        elif ctx.state == states.h11_process:

            # This is the most critical part of making the server run
            # asynchronously. So, each event is processed once, then
            # the loop will be broken.

            """
            Check if event
            If there is no event:
                Receive data
                Get events
                Store events
            Else:
                Get event
                Handle event

            Break
            """
            event = ctx.h1conn.next_event()

            if event is h11.NEED_DATA:
                try:
                    data = sock.recv(512)
                    if not data:
                        # Cleanup socket (no data to recv = done)
                        ctx.state = states.cleanup

                except (BlockingIOError, ssl.SSLWantReadError):
                    # Do not close socket because there could still be more data
                    # TODO: ssl.SSLWantRead error shouldn't be called
                    return

                ctx.h1conn.receive_data(data)
            else:
                if isinstance(event, h11.Request):
                    # In /test/servers/http_echo.py, there is request information stored.
                    # So far, none of this data is used.
                    return
                elif isinstance(event, h11.Data):
                    ctx.buf += event.data

                    return

                elif isinstance(event, h11.EndOfMessage):
                    ctx.future.set_result(ctx.buf)
                    """
                    # Send back
                    # Create response
                    resp = h11.Response(
                        status_code=200,
                        # Use appropriate headers
                        headers=[
                            (b"Content-Type", b"application/dns-message"),
                            (b"Content-Length", str(len(ctx.buf)).encode()),
                        ],
                        # Send back via same version
                        # http_version=http_version,
                        http_version=b"1.1",  # TODO: Does does this support 1.0?
                    )
                    # Send backk all stuff needed
                    sock.send(ctx.h1conn.send(resp))
                    sock.send(ctx.h1conn.send(h11.Data(ctx.buf)))
                    sock.send(ctx.h1conn.send(h11.EndOfMessage()))
                    """

                    return

        elif ctx.state == states.cleanup:
            self.sel.unregister(sock)
            sock.close()
            return

    def _thread_handler(self):
        while self.sel.is_open and (not self.shutdown_event.is_set()):
            events = self.sel.safe_select(timeout=1)  # TODO: Timeout
            with self.lock:  # TODO: Lock here?
                for key, mask in events:
                    if key.fileobj in self.pending_requests.keys():
                        if mask & selectors.EVENT_READ:
                            # TODO: Try except
                            sock = cast(ssl.SSLSocket, key.fileobj)
                            # Don't error if no key
                            # future = self.pending_requests.pop(sock, None)
                            ctx = self.pending_requests.get(sock)
                            if not ctx:
                                continue
                            # TODO: Conn is stored in pending_requests

                            result = self.handle_state(sock, ctx)
                            if result:  # TODO: This doesn't do anything
                                continue

    def forward(
        self,
        query: DNSQuery,
        addr: tuple[str, int],
        host: str,
        path: str = "/dns-query",
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> concurrent.futures.Future[bytes]:

        # TODO: Resolve host using DNS. This might require me creating a public API.
        future: concurrent.futures.Future[bytes] = concurrent.futures.Future()
        try:

            to_send = query.pack()

            sock = socket.create_connection(addr, timeout=5)

            if self.use_tls:
                if not ssl_ctx:
                    ssl_ctx = ssl.create_default_context()
                # TODO: Set alpn protocol
                ssl_ctx.set_alpn_protocols(["http/1.1"])
                sock = ssl_ctx.wrap_socket(sock, server_hostname=host)

            sock.setblocking(False)

            conn = h11.Connection(h11.CLIENT)
            request = h11.Request(
                method="POST",
                target=path,
                headers=[
                    ("Host", host),
                    ("Content-Type", "application/dns-message"),
                    ("Content-Length", str(len(to_send))),
                    ("Connection", "close"),
                ],
            )

            # TODO: Wait for socket ready
            header = conn.send(request)
            body = conn.send(h11.Data(data=to_send))
            end = conn.send(h11.EndOfMessage())
            sock.sendall(header + body + end)

            with self.lock:
                self.sel.register_or_modify(sock, selectors.EVENT_READ)
                # self.pending_requests[sock] = (future, h11.Connection(h11.CLIENT), b"")
                self.pending_requests[sock] = ConnectionContext(
                    future, states.ssl_handshake, None, None
                )

        except Exception as e:
            future.set_exception(e)
            try:
                sock.close()
            except:
                pass

        return future

    def cleanup(self):
        with self.lock:
            for sock in self.pending_requests.keys():  # explicit
                sock.close()

        self.shutdown_event.set()


if __name__ == "__main__":
    import sys

    # TODO: Remove ssl_ctx param from .forward
    ssl.create_default_context = ssl._create_unverified_context  # type: ignore

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    query = DNSQuery(questions=[DNSQuestion(decoded_name="google.com")])
    f = HttpOneForwarder()

    future = f.forward(
        query, (sys.argv[1], int(sys.argv[2])), host=sys.argv[3], ssl_ctx=ssl_ctx
    )
    # future = f.forward(query, ("1.1.1.1", 443), host="cloudflare-dns.com")

    result = future.result()
    print(result)

    f.cleanup()

    resp = DNSQuery.from_bytes(result)
    print(resp)
