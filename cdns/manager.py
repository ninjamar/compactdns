# compactdns
# A simple forwarding DNS server with blocking capabilities
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

import code
import concurrent.futures
import json
import logging
import secrets
import selectors
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

from .protocol import (DNSAnswer, DNSHeader, DNSQuestion, pack_all_compressed,
                       unpack_all)
from .response import ResponseHandler
from .storage import RecordStorage

MAX_WORKERS = 1000


class ServerManager:
    """A class to store a server session."""

    def __init__(
        self,
        host: tuple[str, int],
        shell_host: tuple[str, int],
        resolver: tuple[str, int],
        storage: RecordStorage,
        # max_cache_length: int = float("inf"),
        tls_host: tuple[str, int] | None = None,
        ssl_key_path: str | None = None,
        ssl_cert_path: str | None = None,
        # zone_dir: str | None = None,
        # cache_path: str | None = None,
    ) -> None:
        """
        Create a ServerManager instance.

        Args:
            host: Host and port of server for UDP and TCP.
            shell_host: Host and port of the shell server.
            resolver: Host and port of resolver.
            storage: Storage of zones and cache.
            tls_host: Host and port of server for DNS over TLS.. Defaults to None.
            ssl_key_path: Path to SSL key file. . Defaults to None.
            ssl_cert_path: Path to SSL cert file. Defaults to None.
        """

        self.host = host
        self.shell_host = shell_host
        self.tls_host = tls_host

        # Bind in _start_threaded_udp
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind in _start_threaded_tcp
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.setblocking(False)

        # Make sure all of these are not none
        if all([x is not None for x in [tls_host, ssl_key_path, ssl_cert_path]]):
            self.use_tls = True

            self.tls_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tls_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tls_sock.setblocking(False)

            # TODO: SSL optional
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(
                certfile=ssl_cert_path, keyfile=ssl_key_path  # type: ignore
            )
        else:
            self.use_tls = False

        # Use UDP for shell
        self.shell_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shell_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.shell_secret = secrets.token_hex(10)

        # self.resolver_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.resolver_udp_sock.setblocking(False)

        self.resolver_addr = resolver

        self.forwarder_sel = selectors.DefaultSelector()
        self.forwarder_pending_requests: dict[
            socket.socket, concurrent.futures.Future
        ] = {}

        self.forwarder_thread = threading.Thread(target=self.forwarder_daemon)
        self.forwarder_thread.start()
        self.forwarder_lock = threading.Lock()

        self.execution_timeout = 0
        self.max_workers = MAX_WORKERS

        # self.cache = TimedCache(max_length=max_cache_length)
        self.storage = storage

        # TODO: len self.storage
        # if len(self.records) > max_cache_length:  # FIXME: > or >=? can't decide
        #    logging.warning(
        #        "The Records has %i items, the max cache length is %i",
        #        len(self.records),
        #        max_cache_length,
        #    )

        # TODO: preload zones into cache

    def forwarder_daemon(self) -> None:
        """
        Handler for the thread that handles the response for forwarded queries
        """
        while True:
            events = self.forwarder_sel.select(timeout=0)  # TODO: Timeout
            with self.forwarder_lock:
                for key, mask in events:
                    # TODO: Try except
                    sock = key.fileobj
                    # Don't error if no key
                    future = self.forwarder_pending_requests.pop(sock, None)
                    if future:
                        try:
                            # TODO: Support responses larger longer than 512 using TCP
                            response, _ = sock.recvfrom(512)
                            future.set_result(response)
                        except Exception as e:
                            future.set_exception(e)
                        finally:
                            self.forwarder_sel.unregister(sock)
                            sock.close()

    def forward_dns_query(self, query: bytes) -> concurrent.futures.Future[bytes]:
        """Forward a DNS query to an address.

        Args:
            query: The DNS query to forward.

        Returns:
            The response from the forwarding server.
        """
        # TODO: If using TCP, use a different socket (can be same, even though overhead -- much less tcp requests)
        # TODO: If TC, use either TLS or UDP with multiple packets
        # TODO: TC flag?

        # new socket for each request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        future = concurrent.futures.Future()

        # TODO: The bottleneck

        try:
            sock.sendto(query, self.resolver_addr)
            with self.forwarder_lock:
                # Add a selector, and when it is ready, read from pending_requests
                self.forwarder_sel.register(sock, selectors.EVENT_READ)
                self.forwarder_pending_requests[sock] = future

        except Exception as e:
            future.set_exception(e)
            sock.close()
        return future

    def done(self) -> None:
        """Handle destroying the sockets."""
        self.udp_sock.close()
        self.tcp_sock.close()

        if self.use_tls:
            self.tls_sock.close()

        for sock in self.forwarder_pending_requests.keys():
            sock.close()

    def _handle_dns_query_udp(self, addr: tuple[str, int], query: bytes) -> None:
        """Handle a DNS query over UDP.

        Args:
            addr: Address of client.
            query: Incoming DNS query.
        """
        return ResponseHandler(
            storage=self.storage,
            forwarder=self.forward_dns_query,
            udp_sock=self.udp_sock,
            udp_addr=addr,
        ).start(query)

    def _handle_dns_query_tcp(self, conn: socket.socket) -> None:
        """Handle a DNS query over TCP.

        Args:
            conn: TCP connection.
        """
        # TODO: Timeout

        sel = selectors.DefaultSelector()
        sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE)

        has_conn = True
        while has_conn:
            # Connection times out in two minutes
            events = sel.select(timeout=60 * 2)
            for key, mask in events:
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
                    return ResponseHandler(
                        storage=self.storage,
                        forwarder=self.forward_dns_query,
                        tcp_conn=conn,
                    ).start(query)

    def _handle_dns_query_tls(self, conn: socket.socket) -> None:
        """
        Handle a DNS query over tls.

        Args:
            conn: The TLS connection.
        """
        tls = self.ssl_context.wrap_socket(
            conn, server_side=True, do_handshake_on_connect=False
        )  # handshake on connect is false because this socket is non-blocking
        sel = selectors.DefaultSelector()
        sel.register(tls, selectors.EVENT_READ | selectors.EVENT_WRITE)

        has_handshake = False
        while not has_handshake:
            # 2 second timeout for handshake
            events = sel.select(timeout=2)
            for key, mask in events:
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
        return self._handle_dns_query_tcp(tls)

    def command(self, cmd, **kwargs) -> None:
        """
        Call a command.

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
            return self.storage.load_cache_from_file(
                path=Path(kwargs["path"]).resolve()
            )
        elif cmd == "dump-cache":
            return self.storage.write_cache_to_file(path=Path(kwargs["path"]).resolve())
        elif cmd == "purge-cache":
            return self.storage.cache.purge()

    def _handle_shell_session(self, conn: socket.socket) -> None:
        """
        Handle a shell session. This function blocks the DNS queries,
        and starts an interactive debugging sesion. A secret is needed
        in order for verification. This function will wait until the,
        secret is sent before starting the interpreter.

        Running a command
        >>> self.command("dump-cache", path="path/to/cache/dump")

        Args:
            conn: TCP connection
        """

        secret, addr = conn.recvfrom(len(self.shell_secret))
        if secret.decode() != self.shell_secret:
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
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            sys.stdin = sys.__stdin__
        conn.close()

    def start(self) -> None:
        """Start the server."""
        # TODO: Configure max workers

        self.shell_sock.bind(self.shell_host)
        self.shell_sock.listen(self.max_workers)

        logging.info(
            "Shell server running at %s:%s via UDP.",
            self.shell_host[0],
            self.shell_host[1],
        )
        logging.info("Shell secret: %s", self.shell_secret)

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

        sockets = [self.shell_sock, self.udp_sock, self.tcp_sock]
        if self.use_tls:
            sockets.append(self.tls_sock)

        # Select a value when READ is available
        sel = selectors.DefaultSelector()
        for sock in sockets:
            sel.register(sock, selectors.EVENT_READ)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            try:
                while True:
                    try:
                        # FIXME: What should the timeout be? Does this fix the issue?
                        events = sel.select(timeout=0)
                        for key, mask in events:
                            sock = key.fileobj  # type: ignore[assignment]

                            if sock == self.udp_sock:
                                # TODO: Should receiving data be in the thread? (what)
                                query, addr = self.udp_sock.recvfrom(512)

                                future = executor.submit(
                                    self._handle_dns_query_udp, addr, query
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )
                            elif sock == self.tcp_sock:
                                conn, addr = self.tcp_sock.accept()
                                # Make connection non-blocking
                                conn.setblocking(False)

                                future = executor.submit(
                                    self._handle_dns_query_tcp, conn
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )
                            # If self.use_tls is False, then sockets won't contain self.tls_sock
                            elif sock == self.tls_sock:
                                conn, addr = self.tls_sock.accept()
                                conn.setblocking(False)
                                future = executor.submit(
                                    self._handle_dns_query_tls, conn
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )
                            elif sock == self.shell_sock:
                                conn, addr = self.shell_sock.accept()
                                future = executor.submit(
                                    self._handle_shell_session, conn
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )

                    except KeyboardInterrupt:
                        # Don't want the except call here to be called, I want the one outside the while loop
                        raise KeyboardInterrupt
                    except:
                        logging.error("Error", exc_info=True)

            except KeyboardInterrupt:
                logging.info("KeyboardInterrupt: Server shutting down")
                sys.exit()

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
        except:
            logging.error("Error", exc_info=True)
