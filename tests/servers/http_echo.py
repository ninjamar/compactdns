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


import sys
import selectors

import h11
import ssl
import base64
import urllib
import threading
import socket

import h2.config
import h2.connection
import h2.events
from typing import Callable

from cdns.smartselector import get_current_thread_selector


PKT_SIZE = 1024

def _handle_doh_http1(conn: ssl.SSLSocket):
    # TODO: Document all of this
    h1conn = h11.Connection(h11.SERVER)  # TODO: Use a better variable name for this
    version = None
    headers = {}
    body = b""

    path = None
    method = None
    http_version = None

    sel = get_current_thread_selector()

    sel.register_or_modify(conn, selectors.EVENT_READ)
    # Exhaust all data
    while sel.is_open:
        events = sel.safe_select(timeout=1)
        for key, mask in events:
            if key.fileobj == conn: # is or equals
                try:
                    data = conn.recv(PKT_SIZE)  # TODO: How much should be recieved in one pass?
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    break # leave for loop, not continue on next iteration

                if not data:
                    raise ConnectionResetError
                
                # This probably streams data
                h1conn.receive_data(data)

                for event in iter(h1conn.next_event, h11.NEED_DATA):
                    # This use of iter is called a sentinel pattern
                    if isinstance(event, h11.Request):
                        # Get info
                        path = event.target
                        method = event.method
                        http_version = event.http_version

                        # Normalize headers
                        # HTTP is case insensitive

                        # TODO: Ensure this is bytes
                        headers = {k.lower(): v for k, v in event.headers}
                    elif isinstance(event, h11.Data):
                        body += event.data
                    elif isinstance(event, h11.EndOfMessage):
                        # Utility function to send back
                        def doh_send_back(data: bytes):
                            # Create response
                            resp = h11.Response(
                                status_code=200,
                                # Use appropriate headers
                                headers=[
                                    (b"Content-Type", b"application/dns-message"),
                                    (b"Content-Length", str(len(data)).encode()),
                                ],
                                # Send back via same version
                                # http_version=http_version,
                                http_version=b"1.1",  # TODO: Does does this support 1.0?
                            )
                            # Send backk all stuff needed
                            conn.send(h1conn.send(resp))
                            conn.send(h1conn.send(h11.Data(data)))
                            conn.send(h1conn.send(h11.EndOfMessage()))

                        doh_send_back(body)
                        # TODO: Document
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()

                        return

def _send_doh_http1_error(
    h1conn: h11.Connection,
    conn: ssl.SSLSocket,
    http_version: bytes,
    status_code: int,
) -> None:
    # TODO: Document
    resp = h11.Response(
        status_code=status_code,
        headers=[(b"Content-Length", b"0")],
        http_version=http_version,
        reason=b"Error",  # TODO: Customize
    )
    conn.send(h1conn.send(resp))
    conn.send(h1conn.send(h11.EndOfMessage()))

def _send_doh_http2_error(
        h2conn: h2.connection.H2Connection,
        conn: ssl.SSLSocket,
        stream_id: int,
        status: int,
    ) -> None:
        h2conn.send_headers(
            stream_id, headers=[(b":status", str(status).encode())], end_stream=True
        )
        conn.send(h2conn.data_to_send())

def _handle_doh_http2(conn: ssl.SSLSocket) -> None:
    # Initiate connection
    config = h2.config.H2Configuration(client_side=False)
    h2conn = h2.connection.H2Connection(config)
    h2conn.initiate_connection()

    conn.send(h2conn.data_to_send())

    streams: dict[int, bytes] = {}


    sel = get_current_thread_selector()
    sel.register_or_modify(conn, selectors.EVENT_READ)
    # Exhaust all data

    while sel.is_open:
        events = sel.safe_select(timeout=1)
        for key, mask in events:
            if key.fileobj == conn:
                try:
                    data = conn.recv(PKT_SIZE)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    break

                if not data:
                    raise ConnectionResetError

                for event in h2conn.receive_data(data):
                    stream_id: int = getattr(event, "stream_id", None)

                    # Not all events have a stream_id
                    if stream_id is None:
                        continue
                    # if not stream_id:
                    #    raise ConnectionResetError

                    if isinstance(event, h2.events.RequestReceived):
                        streams[stream_id] = b""  # POST

                    elif isinstance(event, h2.events.DataReceived):
                        if not event.data:
                            raise ConnectionResetError
                        streams[stream_id] += event.data
                        h2conn.acknowledge_received_data(
                            event.flow_controlled_length, stream_id
                        )

                    elif isinstance(event, h2.events.StreamEnded):
                        # Utility function to send back
                        def doh_send_back(data: bytes) -> None:
                            h2conn.send_headers(
                                stream_id,
                                headers=[
                                    (b":status", b"200"),
                                    (b":content-type", b"application/dns-message"),
                                    (b":content-length", str(len(data)).encode()),
                                ],
                            )
                            h2conn.send_data(stream_id, data=data, end_stream=True)
                            conn.send(h2conn.data_to_send())

                        doh_send_back(streams.pop(stream_id))

                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()

                        return

def _doh_router(conn: ssl.SSLSocket) -> None:
    # Router
    # ALPN: ["http/1.1", "h2"]. If ALPN is unknown, then fallback to http/1.0
    proto = conn.selected_alpn_protocol() or "http/1.1"

    if proto == "h2":  # http/2
        _handle_doh_http2(conn)
    else:  # http/1
        _handle_doh_http1(conn)

def _perform_tls_handshake(
    ctx: ssl.SSLContext,
    conn: socket.socket,
) -> ssl.SSLSocket:  # TODO: Type annotations return
    """Handle a DNS query over tls.

    Args:
        conn: The TLS connection.
    """
    tls = ctx.wrap_socket(
        conn, server_side=True, do_handshake_on_connect=False
    )  # handshake on connect is false because this socket is non-blocking
    sel = get_current_thread_selector()

    sel.register_or_modify(tls, selectors.EVENT_READ | selectors.EVENT_WRITE)

    has_handshake = False

    while sel.is_open and (not has_handshake):
        # 2 second timeout for handshake
        events = sel.safe_select(timeout=2)
        for key, mask in events:
            if key.fileobj == tls:
                try:
                    tls.do_handshake()
                    sel.unregister(tls)

                    has_handshake = True
                    break
                except ssl.SSLWantReadError:
                    # Wait until next time
                    pass
                except ssl.SSLWantWriteError:
                    # Wait for more data
                    pass

    # TODO: Should I be returning here?
    return tls
    
def _handle_dns_query_doh(ssl_ctx, conn: socket.socket) -> None:
    tls = _perform_tls_handshake(ssl_ctx, conn)
    return _doh_router(tls)

    
if __name__ == "__main__":
    doh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    doh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    doh_sock.setblocking(False)

   

    doh_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    doh_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    doh_ssl_ctx.load_cert_chain(
        certfile="ignore/dohcert.pem", keyfile="ignore/dohkey.pem"
    )
    doh_ssl_ctx.set_alpn_protocols(
        ["h2", "http/1.1"]
    )  # Need ALPN protocols for DoH


    doh_sock.bind((sys.argv[1], int(sys.argv[2])))
    doh_sock.listen()

    sel = get_current_thread_selector()
    sel.register_or_modify(doh_sock, selectors.EVENT_READ)


    try:
        # Don't check for sel closing as this is the main thread
        while True:
            events = sel.select(timeout=1)
            for key, mask in events:
                if key.fileobj == doh_sock:
                    if mask & selectors.EVENT_READ:
                        conn, addr = doh_sock.accept()
                        conn.setblocking(False)

                        print("Recieved data")

                        _handle_dns_query_doh(doh_ssl_ctx, conn)

                        print("Data echoed back")
    except Exception as e:
        raise e
    finally:
        sel.close()
