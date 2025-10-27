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

import base64
import code
import concurrent.futures
import logging
import multiprocessing as mp
import secrets
import selectors
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Callable, Type, cast

import h2.config
import h2.connection
import h2.events
import h11

from cdns import daemon
from cdns.resolvers import BaseResolver, RecursiveResolver
from cdns.smartselector import close_all_selectors, get_current_thread_selector
from cdns.utils import get_dns_servers

from .response import make_response_handler, mixins, preload_hosts
from .storage import RecordStorage

MAX_WORKERS = 1000  # TODO: What should this be

UDP_PKT_SIZE = 512  # UDP is ALWAYS 512 bytes


# TODO: Read these and implement changes
# https://www.kegel.com/c10k.html
# https://highscalability.com/the-secret-to-10-million-concurrent-connections-the-kernel-i/
# https://www.datacamp.com/tutorial/python-garbage-collection
# https://instagram-engineering.com/dismissing-python-garbage-collection-at-instagram-4dca40b29172

# TODO: Figure out most used sites in a given time period, and preload those sites
# TODO: If using a browser, show a custom block page and then have the option to continue (pass a bypass flag maybe?)


class ServerManager:
    """A class to store a server session."""

    def __init__(
        self,
        host: tuple[str, int],
        debug_shell_host: tuple[str, int],
        resolver: BaseResolver,
        # resolvers: list[tuple[str, int]],
        storage: RecordStorage,
        tls_host: tuple[str, int] | None = None,
        ssl_key_path: str | None = None,
        ssl_cert_path: str | None = None,
        doh_host: tuple[str, int] | None = None,
        doh_key_path: str | None = None,
        doh_cert_path: str | None = None,
        max_workers: int = MAX_WORKERS,
        resolver_list: list[tuple[str, int]] | None = None,
        daemon_options: dict = {},
    ) -> None:
        # TODO: document
        """Create a ServerManager instance.

        Args:
            host: Host and port of server for UDP and TCP.
            shell_host: Host and port of the shell server.
            resolvers: Host and port of resolver.
            storage: Storage of zones and cache.
            tls_host: Host and port of server for DNS over TLS.. Defaults to None.
            ssl_key_path: Path to SSL key file. . Defaults to None.
            ssl_cert_path: Path to SSL cert file. Defaults to None.
        """
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGTERM, self._sigterm_handler)

        # TODO: Make this better
        # Sockets
        self.host = host
        self.debug_shell_host = debug_shell_host
        self.tls_host = tls_host
        self.doh_host = doh_host

        # Bind in _start_threaded_udp
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind in _start_threaded_tcp
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.setblocking(False)

        # Make sure all of these are not none
        if (
            self.tls_host is not None
            and ssl_key_path is not None
            and ssl_cert_path is not None
        ):
            self.use_tls = True

            self.tls_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tls_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tls_sock.setblocking(False)

            self.tls_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.tls_ssl_ctx.load_cert_chain(
                certfile=ssl_cert_path, keyfile=ssl_key_path
            )
        else:
            self.use_tls = False
            self.tls_sock = None

        if (
            self.doh_host is not None
            and doh_cert_path is not None
            and doh_key_path is not None
        ):  # TODO: Add condition for DoH
            self.use_doh = True

            self.DOH_PKT_SIZE = 1024
            self.doh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.doh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.doh_sock.setblocking(False)

            self.doh_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.doh_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.doh_ssl_ctx.load_cert_chain(
                # certfile="ignore/dohcert.pem", keyfile="ignore/dohkey.pem"
                certfile=doh_cert_path,
                keyfile=doh_key_path,
            )
            self.doh_ssl_ctx.set_alpn_protocols(
                ["h2", "http/1.1"]
            )  # Need ALPN protocols for DoH

            self.DOH_GET_PATH = b"/dns-query"
            self.DOH_POST_PATH = b"/dns-query"
        else:
            self.use_doh = False
            self.doh_sock = None

        if self.debug_shell_host is not None:
            self.use_debug_shell = True
            # Use UDP for shell
            self.debug_shell_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_shell_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.debug_shell_secret = secrets.token_hex(10)
        else:
            self.use_debug_shell = False
            self.debug_shell_sock = None

        # Other config. TODO: Implement better configuration here
        self.execution_timeout = 0
        self.max_workers = max_workers

        self.tracker = mixins.ResourceTrackerMixin()  # also doubles as a dictionary

        self.smart_mixin_input_queue = mp.Queue()

        # smart_mixin =  mixins.SmartEnsureLoadedMixin(self.smart_mixin_input_queue)

        self.ResponseHandler = make_response_handler(
            "ResponseHandler",
            # mixins=[smart_mixin, self.tracker],
            mixins=[self.tracker],
        )

        # d = daemon.SmartEnsureLoadedDaemon(smart_mixin, self.smart_mixin_input_queue, interval=1, queue=Queue(), udp_addr=self.host)
        # d.start()

        self.storage = storage

        # Complicated resolver stuff
        self.resolver = resolver

    def _sigterm_handler(self, stack, frame) -> None:
        """Handler for SIGTERM event."""
        logging.info("Recieved SIGTERM")
        self.shutdown_event.set()

    @classmethod
    def from_config(cls, kwargs):
        """Create an instance of ServerManager from a configuration.

        Returns:
            An instance of ServerManager
        """

        # kwargs isn't **kwargs because '.' isn't a valid variable name

        storage = RecordStorage()
        if kwargs["storage.zone_dirs"] is not None:
            for dir in kwargs["storage.zone_dirs"]:
                p = Path(dir).resolve()
                p.parent.mkdir(parents=True, exist_ok=True)
                storage.load_zones_from_dir(p)
        if kwargs["storage.zone_path"] is not None:
            p = Path(kwargs["storage.zone_path"]).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            storage.load_zone_object_from_file(p)
            storage._zone_path = kwargs["storage.zone_path"]

        if kwargs["storage.cache_path"] is not None:
            # TODO: Test this out
            p = Path(kwargs["storage.cache_path"]).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            storage.load_cache_from_file(p)
            storage._cache_path = kwargs["storage.cache_path"]

        if (
            kwargs["servers.debug_shell.host"] is None
            or kwargs["servers.debug_shell.port"] is None
        ):
            debug_shell_host = None
        else:
            debug_shell_host = (
                kwargs["servers.debug_shell.host"],
                int(kwargs["servers.debug_shell.port"]),
            )

        if kwargs["servers.tls.host"] is None or kwargs["servers.tls.port"] is None:
            tls_host = None
        else:
            tls_host = (kwargs["servers.tls.host"], int(kwargs["servers.tls.port"]))

        if kwargs["servers.doh.host"] is None or kwargs["servers.doh.port"] is None:
            doh_host = None
        else:
            doh_host = (kwargs["servers.doh.host"], int(kwargs["servers.doh.port"]))

        if kwargs["resolver.doh_endpoints"] is not None:
            doh_endpoints = [tuple(item) for item in kwargs["resolver.doh_endpoints"]]
        else:
            doh_endpoints = None

        if kwargs["resolver.tls_endpoints"] is not None:
            tls_endpoints = [tuple(item) for item in kwargs["resolver.tls_endpoints"]]
        else:
            tls_endpoints = None

        # TODO: Normalize case for arguments
        resolver = RecursiveResolver(
            forwarding_mode=kwargs["resolver.forwarding_mode"].lower(),
            doh_endpoints=doh_endpoints,
            tls_endpoints=tls_endpoints,
        )

        if kwargs["storage.preload_path"]:
            if not isinstance(resolver, RecursiveResolver):
                logging.warning(
                    "Preloading hosts without a recursive resolver doesn't bring significant speed improvements"
                )

            with open(kwargs["storage.preload_path"]) as f:
                hosts = [x.strip() for x in f.readlines() if not x.startswith("#")]

            # TODO: Is this ok?
            preload_hosts(hosts, storage, resolver)

        logging.debug("Records: %s", storage)
        return cls(
            storage=storage,
            host=(kwargs["servers.host.host"], int(kwargs["servers.host.port"])),
            debug_shell_host=debug_shell_host,
            resolver=resolver,
            tls_host=tls_host,  # TODO: host vs addr
            ssl_key_path=kwargs["servers.tls.ssl_key"],
            ssl_cert_path=kwargs["servers.tls.ssl_cert"],
            doh_host=doh_host,
            doh_key_path=kwargs["servers.doh.ssl_key"],
            doh_cert_path=kwargs["servers.doh.ssl_cert"],
            max_workers=kwargs["all.max_workers"],
            daemon_options={
                k[8:]: v for k, v in kwargs.items() if k.startswith("daemon")
            },
            # daemon_options=kwargs["daemons"]
        )

    def cleanup(self) -> None:
        """Handle destroying the sockets."""
        # Selectors are closed automatically when appropriate thread exits

        close_all_selectors()

        self.udp_sock.close()
        self.tcp_sock.close()

        if self.use_tls:
            self.tls_sock.close()

        if self.use_debug_shell:
            self.debug_shell_sock.close()

        # TODO: Hack
        if hasattr(self, "resolver_daemon"):
            self.resolver_daemon.terminate()

        self.resolver.cleanup()

        logging.info("Cleanup: Sockets closed")
        # Dump cache and zones to file
        if self.storage._cache_path:
            logging.info("Cleanup: Writing cache to file %s", self.storage._cache_path)
            self.storage.write_cache_to_file(self.storage._cache_path)
        if self.storage._zone_path:
            logging.info("Cleanup: Writing zone to file %s", self.storage._zone_path)
            self.storage.write_zone_object_to_file(self.storage._zone_path)

    def _handle_dns_query_udp(
        self, addr: tuple[str, int], query: bytes, rt_info=0
    ) -> None:
        """Handle a DNS query over UDP.

        Args:
            addr: Address of client.
            query: Incoming DNS query.
        """
        return self.ResponseHandler(
            storage=self.storage,
            resolver=self.resolver,
            udp_sock=self.udp_sock,
            udp_addr=addr,
        ).start(query)

    def _handle_dns_query_tcp(self, conn: socket.socket | ssl.SSLSocket) -> None:
        """Handle a DNS query over TCP.

        Args:
            conn: TCP connection.
        """
        # TODO: Timeout

        sel = get_current_thread_selector()

        sel.register_or_modify(conn, selectors.EVENT_READ | selectors.EVENT_WRITE)
        has_conn = True
        while sel.is_open and has_conn:
            # Connection times out in two minutes
            events = sel.safe_select(timeout=60 * 2)
            for key, mask in events:
                if key.fileobj == conn:
                    # sock = key.fileobj
                    if conn.fileno() == -1:
                        has_conn = False
                        break
                    if mask & selectors.EVENT_READ:
                        # 2 bytes for size of message first
                        length = conn.recv(2)
                        if not length:
                            has_conn = False
                            break
                        length = struct.unpack("!H", length)[0]
                        query = conn.recv(int(length))

                        if not query:
                            has_conn = False
                            # TODO: Should an error be raised here?

                            break  # TODO: Is this fine
                        return self.ResponseHandler(
                            storage=self.storage,
                            resolver=self.resolver,
                            tcp_conn=conn,
                            # Easy way to add TLS mode without refactoring a lot of previous code
                            tls=isinstance(conn, ssl.SSLSocket),
                        ).start(query)

    def _handle_dns_query_tls(self, conn: socket.socket) -> None:
        tls = self._perform_tls_handshake(self.tls_ssl_ctx, conn)
        return self._handle_dns_query_tcp(tls)

    def _handle_dns_query_doh(self, conn: socket.socket) -> None:
        tls = self._perform_tls_handshake(self.doh_ssl_ctx, conn)
        return self._doh_router(tls)

    # TODO: A lot of underscores in names
    def _doh_router(self, conn: ssl.SSLSocket) -> None:
        # Router
        # ALPN: ["http/1.1", "h2"]. If ALPN is unknown, then fallback to http/1.0
        proto = conn.selected_alpn_protocol() or "http/1.1"
        if proto == "h2":  # http/2
            self._handle_doh_http2(conn)
        else:  # http/1
            self._handle_doh_http1(conn)

    def _handle_doh_http1(self, conn: ssl.SSLSocket):
        # TODO: Document all of this
        h1conn = h11.Connection(h11.SERVER)  # TODO: Use a better variable name for this

        headers = {}
        body = b""

        path = None
        method = None
        http_version = None

        # Exhaust all data'
        sel = get_current_thread_selector()

        sel.register_or_modify(conn, selectors.EVENT_READ)
        while sel.is_open:
            events = sel.safe_select(timeout=1)
            for key, mask in events:
                if key.fileobj == conn:  # is or equals

                    try:
                        data = conn.recv(
                            self.DOH_PKT_SIZE
                        )  # TODO: How much should be recieved in one pass?
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError) as e:
                        break  # leave for loop, not continue on next iteration
                    if not data:
                        # No data
                        # TODO: Close connection when this happens
                        # TODO: Automatically close expired connections
                        raise ConnectionResetError

                    # h11 is a parser -- start parsing the data
                    h1conn.receive_data(data)

                    # Go through each event
                    for event in iter(h1conn.next_event, h11.NEED_DATA):
                        # This use of iter is called a sentinel pattern
                        # It is equivlent to:
                        # while True:
                        #     event = h1conn.next_event()
                        #     if event == h11.NEED_DATA:
                        #         break
                        # This pattern seems useful for IO, so I should use it more
                        # TODO: Refactor code to use the sentinel pattern

                        # Headers
                        if isinstance(event, h11.Request):
                            # Get info
                            path = event.target
                            method = event.method
                            http_version = event.http_version

                            # Normalize headers
                            # HTTP is case insensitive
                            headers = {k.lower(): v for k, v in event.headers}

                            if method == b"GET":

                                # Validate path inside here
                                if not path.startswith(self.DOH_GET_PATH):
                                    # Error invalid path
                                    return self._send_doh_http1_error(
                                        h1conn, conn, http_version, 404
                                    )  # page not found

                            elif method == b"POST":

                                # Error invalid path
                                # TODO: Does path need to be removed slashed?
                                if path != self.DOH_POST_PATH:
                                    return self._send_doh_http1_error(
                                        h1conn, conn, http_version, 404
                                    )  # page not found
                                # Error invalid header
                                if (
                                    headers.get(b"content-type")
                                    != b"application/dns-message"
                                ):
                                    return self._send_doh_http1_error(
                                        h1conn, conn, http_version, 400
                                    )  # malformed request

                                # TODO: Does everything need to be validated here
                            else:
                                # Invalid method, send an error
                                return self._send_doh_http1_error(
                                    h1conn, conn, http_version, 405
                                )
                        # Recieve body
                        elif isinstance(event, h11.Data):
                            # Only triggered for POST
                            # Add body data
                            body += event.data
                        # End of message
                        elif isinstance(event, h11.EndOfMessage):

                            # Missing information
                            if method is None or path is None or http_version is None:
                                return self._send_doh_http1_error(
                                    h1conn, conn, http_version, 400
                                )

                            if method == b"GET":
                                # Stored as /dns-query?dns=AABB
                                # Get every thing after the ? in the url
                                qs = path.decode().split("?", 1)[1]
                                # Get the DNS part
                                qs = urllib.parse.parse_qs(qs)["dns"][
                                    0
                                ]  # TODO: What does this do
                                dns_data = base64.urlsafe_b64decode(
                                    qs
                                    + "=" * (4 - len(qs) % 4) % 4  # Add equals padding
                                )
                            else:
                                # POST data is stored in body
                                dns_data = body

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

                            # TODO: Shutdown conn?
                            return self.ResponseHandler(
                                storage=self.storage,
                                resolver=self.resolver,
                                doh_conn=conn,
                                # New field
                                doh_send_back=doh_send_back,
                            ).start(dns_data)

                            # TODO: Document

    def _send_doh_http1_error(
        self,
        h1conn: h11.Connection,
        conn: ssl.SSLSocket,
        http_version: bytes,
        status_code: int,
    ) -> None:
        body = f"{status_code} Error".encode()
        # TODO: Document
        resp = h11.Response(
            status_code=status_code,
            headers=[
                (b"Content-Length", str(len(body)).encode()),
                (b"Content-Type", b"text/plain"),
                (b"Connection", b"Close"),
            ],
            http_version=http_version,
            reason=b"Error",  # TODO: Customize
        )

        conn.send(h1conn.send(resp))
        conn.send(h1conn.send(h11.Data(body)))
        conn.send(h1conn.send(h11.EndOfMessage()))

    def _send_doh_http2_error(
        self,
        h2conn: h2.connection.H2Connection,
        conn: ssl.SSLSocket,
        stream_id: int,
        status: int,
    ) -> None:
        h2conn.send_headers(
            stream_id, headers=[(b":status", str(status).encode())], end_stream=True
        )
        conn.send(h2conn.data_to_send())

    def _handle_doh_http2(self, conn: ssl.SSLSocket) -> None:
        # Initiate connection
        config = h2.config.H2Configuration(client_side=False)
        h2conn = h2.connection.H2Connection(config)
        h2conn.initiate_connection()

        conn.send(h2conn.data_to_send())

        streams: dict[int, bytes] = {}

        headers_map: dict[int, tuple[bytes, bytes]] = {}

        sel = get_current_thread_selector()
        sel.register_or_modify(conn, selectors.EVENT_READ)

        while sel.is_open:
            events = sel.select(timeout=1)
            for key, mask in events:
                if key.fileobj == conn:
                    try:
                        data = conn.recv(self.DOH_PKT_SIZE)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass

                    if not data:
                        raise ConnectionResetError

                    for event in h2conn.receive_data(data):
                        stream_id: int = getattr(event, "stream_id", None)

                        # Not all events have a stream_id
                        if stream_id is None:
                            continue
                        # if not stream_id:
                        #    # TODO: Is this the right error?
                        #    raise ConnectionResetError

                        if isinstance(event, h2.events.RequestReceived):
                            # TODO: Type annotate everything
                            headers = dict(
                                event.headers
                            )  # list of tuples of (key, value)
                            path = headers[b":path"]
                            method = headers[b":method"]

                            # Only POST and responses needs content type
                            content_type = headers.get(b"content-type", b"")

                            # Routing
                            if method == b"GET":
                                if not path.startswith(self.DOH_GET_PATH):
                                    return self._send_doh_http2_error(
                                        h2conn, conn, stream_id, 400
                                    )
                            elif method == b"POST":
                                if (
                                    path != self.DOH_POST_PATH
                                    or content_type != b"application/dns-message"
                                ):
                                    return self._send_doh_http2_error(
                                        h2conn, conn, stream_id, 400
                                    )
                            else:
                                return self._send_doh_http2_error(
                                    h2conn, conn, stream_id, 405
                                )

                            # Start of request, so setup storage
                            streams[stream_id] = b""  # POST
                            headers_map[stream_id] = (method, path)

                        elif isinstance(event, h2.events.DataReceived):
                            if not event.data:
                                raise ConnectionResetError
                            # Only triggered for POST
                            streams[stream_id] += event.data
                            h2conn.acknowledge_received_data(
                                event.flow_controlled_length, stream_id
                            )

                        elif isinstance(event, h2.events.StreamEnded):
                            # Get method and path from the headers
                            method, path = headers_map.pop(stream_id)

                            if method == b"GET":
                                # Stored as /dns-query?dns=AABB
                                # Get every thing after the ? in the url
                                qs = path.decode().split("?", 1)[1]
                                # Get the DNS part
                                qs = urllib.parse.parse_qs(qs)["dns"][
                                    0
                                ]  # TODO: What does this do
                                dns_data = base64.urlsafe_b64decode(
                                    qs
                                    + "=" * (4 - len(qs) % 4) % 4  # Add equals padding
                                )

                            else:
                                dns_data = streams.pop(stream_id)

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

                            return self.ResponseHandler(
                                storage=self.storage,
                                resolver=self.resolver,
                                doh_conn=conn,
                                # New field
                                doh_send_back=doh_send_back,
                            ).start(dns_data)

    # TODO: Rename these functions to match purposes
    def _perform_tls_handshake(
        self,
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
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        # Wait until next time
                        pass
        # TODO: Should I be returning here?

        return tls

    def command(self, cmd: str, **kwargs) -> None:
        """Call a command.

        | Command Name | Description | Arguments |
        | load-zones   | Load zones from pickle file | Path - path to file |
        | dump-zones   | Dump zones to a pickle file | Path - path to file |
        | load-zones-dir | Load zones from a directory | Path - path to file |
        | load-cache   | Load the cache from a pickle file | Path - path to file |
        | dump-cache   | Write the cache to a pickle file | Path - path to file |
        | purge-cache  | Purge the cache |

        >>> self.command("load-zones-dir", path="./foo/bar")

        Args:
            cmd: Name of the command.
            kwargs: Arguments to the command.
        """
        if cmd == "load-zones-dir":
            return self.storage.load_zones_from_dir(path=Path(kwargs["path"]).resolve())
        elif cmd == "load-zones":
            return self.storage.load_zone_object_from_file(
                path=Path(kwargs["path"]).resolve()
            )
        elif cmd == "dump-zones":
            return self.storage.write_zone_object_to_file(
                path=Path(kwargs["path"]).resolve()
            )
        elif cmd == "load-cache":
            return self.storage.load_cache_from_file(path=Path(kwargs["path"]))
        elif cmd == "dump-cache":
            return self.storage.write_cache_to_file(path=Path(kwargs["path"]).resolve())
        elif cmd == "purge-cache":
            return self.storage.cache.purge()
        elif cmd == "reset-rule-5-mins":
            # Allow site now
            # Set timer to 5 mins in future
            # In 5 minutes, unallow site
            pass

    def _handle_debug_shell_session(self, conn: socket.socket) -> None:
        """Handle a debug shell session. This function blocks the DNS queries,
        and starts an interactive debugging sesion. A secret is needed in order
        for verification. This function will wait until the, secret is sent
        before starting the interpreter.

        Running a command
        >>> self.command("dump-cache", path="path/to/cache/dump")

        Args:
            conn: TCP connection
        """

        old_stdout = sys.stdout
        odl_stderr = sys.stderr
        old_stdin = sys.stdin

        secret, addr = conn.recvfrom(len(self.debug_shell_secret))
        if secret.decode() != self.debug_shell_secret:
            conn.close()
            return

        ctx = {**globals(), **locals()}
        sys.stdout = sys.stderr = conn.makefile("w")
        sys.stdin = conn.makefile("r")
        try:
            code.interact(local=ctx)
        except SystemError:
            pass
        finally:
            sys.stdout = old_stdout
            sys.stderr = odl_stderr
            sys.stdin = old_stdin
        conn.close()

    def start(self) -> None:
        """Start the server."""
        # TODO: Configure max workers

        if self.use_debug_shell:
            self.debug_shell_sock.bind(self.debug_shell_host)
            self.debug_shell_sock.listen(self.max_workers)

            logging.info(
                "Debug shell server running at %s:%s via UDP.",
                self.debug_shell_host[0],
                self.debug_shell_host[1],
            )
            logging.info("Debug shell secret: %s", self.debug_shell_secret)

        self.udp_sock.bind(self.host)
        logging.info("DNS Server running at %s:%s via TCP", self.host[0], self.host[1])

        self.tcp_sock.bind(self.host)
        self.tcp_sock.listen(self.max_workers)
        logging.info("DNS Server running at %s:%s via UDP", self.host[0], self.host[1])

        if self.use_tls:
            self.tls_sock.bind(self.tls_host)  # type: ignore
            self.tls_sock.listen(self.max_workers)
            logging.info(
                "DNS Server running at %s:%s via DNS over TLS",
                self.tls_host[0],  # type: ignore
                self.tls_host[1],  # type: ignore
            )

        if self.use_doh:
            self.doh_host = ("127.0.0.1", 8443)
            self.doh_sock.bind(self.doh_host)
            self.doh_sock.listen(self.max_workers)

            logging.info(
                "DNS Server running at %s:%s via DNS over HTTPS",
                self.doh_host[0],
                self.doh_host[1],
            )

        # Update these devices when it's readable
        sockets = [
            self.udp_sock,
            self.tcp_sock,
        ]
        if self.use_tls:
            sockets.append(self.tls_sock)
        if self.use_doh:
            sockets.append(self.doh_sock)
        if self.use_debug_shell:
            sockets.append(self.debug_shell_sock)

        # Select a value when READ is available
        sel = get_current_thread_selector()

        for obj in sockets:
            sel.register_or_modify(obj, selectors.EVENT_READ)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            try:
                # self.now = time.time()

                # Keep running until shutdown
                # Do not check if the selector is open, because any quit events are called here
                while not self.shutdown_event.is_set():
                    try:
                        # Handle the requests here
                        self._single_event(sel, executor)

                    except KeyboardInterrupt:
                        # Don't want the except call here to be called, I want the one outside the while loop
                        raise KeyboardInterrupt

                    except Exception as e:
                        logging.error("Error", exc_info=True)

            # Once these errors are handled, the context manager finishes, so the executor already finishes
            except KeyboardInterrupt:
                logging.info("Recieved KeyboardInterrupt")

            except OSError as o:
                if o.errno == 24:
                    # When I waked up my MacBook from sleep, the server
                    # crashed. I got OSError: [Errno 24] Too many open files
                    # from all the open sockets.
                    # - ninjamar
                    logging.error("Too many sockets open.")

                logging.error("OSError", exc_info=True)

        self.cleanup()
        logging.info("Server shutdown complete")

    def _single_event(self, sel, executor: concurrent.futures.Executor) -> None:
        """Handle a single event."""
        # if self.now >= 10:
        #    logging.info("Passed health check")
        #    self.now = time.time()

        # TODO: If socket limit exceeded, close all open sockets and warn user
        # FIXME: What should the timeout be? Does this fix the issue?
        # After 1 secs if no socket, the loop condition will be checked again

        # if self.ResponseHandler.lcb.mixins.has(mixins.ResourceTrackerMixin):
        #    if len(self.tracker.keys()) > 0:
        #        logging.error("TRACKER: %s", self.tracker.get_elapsed())

        events = sel.safe_select(timeout=1)
        for key, mask in events:
            obj = key.fileobj  # type: ignore[assignment]
            if obj == self.udp_sock:
                # TODO: Should receiving data be in the thread? (what)
                query, addr = self.udp_sock.recvfrom(UDP_PKT_SIZE)

                future = executor.submit(self._handle_dns_query_udp, addr, query)
                future.add_done_callback(self._handle_thread_pool_completion)
            elif obj == self.tcp_sock:
                conn, addr = self.tcp_sock.accept()
                # Make connection non-blocking
                conn.setblocking(False)

                future = executor.submit(self._handle_dns_query_tcp, conn)
                future.add_done_callback(self._handle_thread_pool_completion)
            # If self.use_tls is False, then sockets won't contain self.tls_sock
            elif obj == self.tls_sock:
                conn, addr = self.tls_sock.accept()
                conn.setblocking(False)

                future = executor.submit(self._handle_dns_query_tls, conn)
                future.add_done_callback(self._handle_thread_pool_completion)

            elif obj == self.doh_sock:
                conn, addr = self.doh_sock.accept()
                conn.setblocking(False)

                future = executor.submit(self._handle_dns_query_doh, conn)
                future.add_done_callback(self._handle_thread_pool_completion)

            elif obj == self.debug_shell_sock:
                # TODO: Maybe only do this on DEBUG mode? But it might be pretty useful
                conn, addr = self.debug_shell_sock.accept()

                future = executor.submit(self._handle_debug_shell_session, conn)
                future.add_done_callback(self._handle_thread_pool_completion)

    def _handle_thread_pool_completion(self, future: concurrent.futures.Future) -> None:
        """Handle the result of a ThreadPoolExecutor.

        Args:
            future: The future from ThreadPoolExecutor.submit()
        """
        try:
            future.result(timeout=self.execution_timeout)
        except concurrent.futures.TimeoutError:
            # TODO: Make this work...
            logging.error("Request handler timed out", exc_info=True)
        except Exception as e:
            logging.error("Error", exc_info=True)
