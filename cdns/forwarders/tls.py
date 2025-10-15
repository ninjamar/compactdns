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

import selectors
import ssl

from cdns.protocol import *

from .tcp import TCPForwarder
from .tcp import states as _states


class states(_states):
    ssl_handshake = 5


class TLSForwarder(TCPForwarder):
    # TCP Forwarder but with SSL layer
    def __init__(self):
        super().__init__()

        self.tls_ctx = ssl.create_default_context()

    def forward(self, query, addr):
        return super().forward(query, addr)

    def _create_socket(self, addr):
        sock = super()._create_socket()
        # sock = self.tls_ctx.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=addr[0]) # addr: ("127.0.0.1", 53)
        return sock

    def _connect(self, sock, addr):
        return super()._connect(sock, addr)

    def _register_connection(self, sock, context, events):
        #
        # context.state = states.ssl_handshake
        events = selectors.EVENT_READ | selectors.EVENT_WRITE

        return super()._register_connection(sock, context, events)

    """
    FLOW:
        [x] connection - READ/WRITE
        [x] ssl - READ/WRITE
        [x] send - WRITE
        [x] read_len - READ
        [x] read_body - READ
    """

    def _handle_ssl_handshake(self, sock, ctx):
        # print("TLS: ssl handshake", ctx.state)
        # print(type(sock), sock._sslobj)
        try:
            sock.do_handshake()
            ctx.state = states.sending
            self.sel.modify(sock, selectors.EVENT_WRITE)
        except ssl.SSLWantReadError:
            # This could just be pass, but it is fine to delegate to the appropriate
            # functions here.
            self.sel.modify(sock, selectors.EVENT_READ)
        except ssl.SSLWantWriteError:
            self.sel.modify(sock, selectors.EVENT_WRITE)

    def _handle_write(self, sock, ctx):
        # print("TLS: writeable", ctx.state)
        if ctx.state == states.connecting:
            super()._handle_write(sock, ctx)

            wrapped = self.tls_ctx.wrap_socket(
                sock, do_handshake_on_connect=False, server_hostname=ctx.addr[0]
            )  # addr: ("127.0.0.1", 53)
            # Move context from sock to wrapped
            self._ctxs[wrapped] = self._ctxs.pop(sock)
            # Move selectors from sock to wrapped
            self.sel.unregister(sock)
            self.sel.register(wrapped, selectors.EVENT_READ | selectors.EVENT_WRITE)

            # After connection, wrap the socket
            ctx.state = states.ssl_handshake
            # self._check_connection(sock)
            # print("TLS: Changing state to handshake")
            # ctx.state = states.ssl_handshake

        elif ctx.state == states.ssl_handshake:
            return self._handle_ssl_handshake(sock, ctx)

        else:
            return super()._handle_write(sock, ctx)

    def _handle_read(self, sock, ctx):
        try:
            # print("TLS: readable", ctx.state)
            if ctx.state == states.ssl_handshake:
                return self._handle_ssl_handshake(sock, ctx)
            else:
                return super()._handle_read(sock, ctx)
        except ssl.SSLWantReadError:
            self.sel.modify(sock, selectors.EVENT_READ)
        except ssl.SSLWantWriteError:
            self.sel.modify(sock, selectors.EVENT_WRITE)


if __name__ == "__main__":
    # HACK: Monkeypatch for testing. In production, the server should be trusted
    ssl.create_default_context = ssl._create_unverified_context  # type: ignore

    f = TLSForwarder()
    q = DNSQuery(DNSHeader(), [DNSQuestion(decoded_name="google.com")])
    res = f.forward(q, ("127.0.0.1", 5353))  # Simple echo server in ignore/echo.py

    result = res.result()
    print(result.hex())

    f.cleanup()

# [x] TODO: Make thread exit cleanly using .cleanup
# TODO: Integrate forwarders config for changing options
# TODO: Add DoH forwarder -- http 1 and http 2
