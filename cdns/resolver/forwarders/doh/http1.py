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
import h11

from cdns.protocol import *

from ..base import BaseForwarder


class HttpOneForwarder(BaseForwarder):
    def __init__(self, use_tls=True):
        if not use_tls:
            logging.warning("Not using TLS for DoH endpoint")
        self.sel = selectors.DefaultSelector()
        self.pending_requests: dict[
            socket.socket, tuple[concurrent.futures.Future, h11.connection.H1Connection, bytes]
        ] = {}

        self.use_tls = use_tls

        self.lock = threading.Lock()

        self.shutdown_event = threading.Event()

        self.thread = threading.Thread(
            target=self._thread_handler
        )  # TODO: Daemon true or false
        self.thread.start()

    def _thread_handler(self):
        while not self.shutdown_event.is_set():
            events = self.sel.select(timeout=1)  # TODO: Timeout
            with self.lock:  # TODO: Lock here?
                for key, mask in events:
                    if mask & selectors.EVENT_READ:
                        # TODO: Try except
                        sock = cast(socket.socket, key.fileobj)
                        # Don't error if no key
                        # future = self.pending_requests.pop(sock, None)
                        future, conn, buffer = self.pending_requests.get(sock)
                        # TODO: Conn is stored in pending_requests
                        if future:
                            try:
                                try:
                                    data = sock.recv(4096)
                                    if not data:
                                        future.set_result(buffer)
                                        self.sel.unregister(sock)
                                        sock.close()
                                except (BlockingIOError, ssl.SSLWantReadError):
                                    break

                                conn.receive_data(data)

                                event = conn.next_event()
                                if isinstance(event, h11.Response):
                                    # Start of message
                                    continue
                                elif isinstance(event, h11.Data):
                                    buffer += event.data  # decoded data
                                    pass
                                elif isinstance(event, h11.EndOfMessage):
                                    self.pending_requests.pop(sock)
                                    future.set_result(buffer)

                                    self.sel.unregister(sock)
                                    sock.close()

                            except Exception as e:
                                future.set_exception(e)
                                self.sel.unregister(sock)
                                sock.close()

    def forward(
        self,
        query: DNSQuery,
        addr: tuple[str, int],
        host: str,
        path: str = "/dns-query",
        ssl_ctx: ssl.SSLContext | None = None
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
                ssl_ctx.set_alpn_protocols(["http/1"])
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

            header = conn.send(request)
            body = conn.send(h11.Data(data=to_send))
            end = conn.send(h11.EndOfMessage())
            sock.sendall(header + body + end)

            with self.lock:
                self.sel.register(sock, selectors.EVENT_READ)
                self.pending_requests[sock] = (future, h11.Connection(h11.CLIENT), b"")

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
    

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    query = DNSQuery(questions=[DNSQuestion(decoded_name="google.com")])
    f = HttpOneForwarder()
    
    future = f.forward(query, (sys.argv[1], int(sys.argv[2])), host=sys.argv[3], ssl_ctx=ssl_ctx)
    # future = f.forward(query, ("1.1.1.1", 443), host="cloudflare-dns.com")

    result = future.result()
    print(result)

    f.cleanup()

    #resp = DNSQuery.from_bytes(result)
    #print(resp)
