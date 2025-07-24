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
import struct

from cdns.protocol import *

from .streams import BaseStreamForwarder, ConnectionContext, states


class TCPForwarder(BaseStreamForwarder):
    def forward(
        self, query: DNSQuery, addr: tuple[str, int]
    ) -> concurrent.futures.Future[bytes]:

        future: concurrent.futures.Future[bytes] = concurrent.futures.Future()

        p = query.pack()
        data = struct.pack("!H", len(p)) + p

        sock = self._create_socket(addr)

        try:
            self._connect(sock, addr)
        except Exception as e:
            future.set_exception(e)
            self._cleanup_sock(sock)
            return future

        self._register_connection(
            sock,
            ConnectionContext(
                future=future,
                state=states.connecting,
                out_buf=data,
                in_len=None,
                in_buf=None,  # TLDR; bytearray() is a mutuable version of bytes()
                addr=addr,
            ),
            selectors.EVENT_WRITE,
        )
        return future

    def _check_connection(self, sock):
        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err, "Socket connection failed")

    def _handle_write(self, sock: socket.socket, ctx: ConnectionContext):
        # TODO: use logging here
        logging.debug("TCP: writeable %s", ctx.state)
        # TODO: Document this whole thing somewhere
        if ctx.state == states.connecting:
            self._check_connection(sock)
            logging.debug("TCP: changing state to sending")
            ctx.state = states.sending
            # Return here -- in TLS, we want to make sure we do the handshale.
            # Since the selector is still writeable, this function will get
            # called to trigger the next part.
        elif ctx.state == states.sending:
            logging.debug("TCP: Sent")
            # Send as much data as possible
            sent = sock.send(ctx.out_buf)
            # Remove sent data from buffer
            # ctx.out_buf = ctx.out_buf[sent:]
            # if not ctx.out_buf:
            logging.debug("TCP: changing state to reading len")
            ctx.state = states.reading_len
            self.sel.modify(sock, selectors.EVENT_READ)

    def _handle_read(self, sock: socket.socket, ctx: ConnectionContext):
        logging.debug("TCP: readable %s", ctx.state)
        if ctx.state == states.reading_len:
            length = sock.recv(2)
            if not length:
                raise ConnectionResetError

            ctx.in_len = struct.unpack("!H", length)[0]

            logging.debug("TCP: changing state to reading data")
            ctx.state = states.reading_data

            # Need to read data immediatly. Sometimes the server will send the
            # response as soon as possible, so the selector will not be triggered
            self.sel.modify(sock, selectors.EVENT_READ)

            return self._handle_read(sock, ctx)

        elif ctx.state == states.reading_data:
            print("reading data")
            buf = sock.recv(ctx.in_len)
            if not buf:
                raise ConnectionResetError

            ctx.in_buf = buf
            logging.debug("TCP: changing state to done")
            ctx.state = states.done

            ctx.future.set_result(ctx.in_buf)

            self._cleanup_sock(sock)


if __name__ == "__main__":
    f = TCPForwarder()
    q = DNSQuery(DNSHeader(), [DNSQuestion(decoded_name="google.com")])
    res = f.forward(q, ("127.0.0.1", 5353))  # Simple echo server in ignore/echo.py

    result = res.result()
    print(result.hex())
