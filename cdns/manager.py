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

import code
import concurrent.futures
import logging
import secrets
import selectors
import socket
import ssl
import struct
import sys
import threading
import time
from multiprocessing import Queue
from pathlib import Path
from typing import Callable, Type, cast

from . import daemon
from .resolver import BaseResolver, RecursiveResolver, UpstreamResolver
from .response import ResponseHandler
from .storage import RecordStorage
from .utils import get_dns_servers

MAX_WORKERS = 1000


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

        # TODO: Make this better
        # Sockets
        self.host = host
        self.debug_shell_host = debug_shell_host
        self.tls_host = tls_host

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

            # TODO: SSL optional
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ssl_context.load_cert_chain(
                certfile=ssl_cert_path, keyfile=ssl_key_path
            )
        else:
            self.use_tls = False

        if self.debug_shell_host is not None:
            self.use_debug_shell = True
            # Use UDP for shell
            self.debug_shell_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_shell_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.debug_shell_secret = secrets.token_hex(10)
        else:
            self.use_debug_shell = False

        # Other config. TODO: Implement better configuration here
        self.execution_timeout = 0
        self.max_workers = max_workers
        self.storage = storage

        # Complicated resolver stuff
        self.resolver = resolver
        if isinstance(self.resolver, RecursiveResolver) and (
            resolver_list or daemon_options.get("fastest_resolver.use")
        ):
            raise ValueError(
                "Unable to have resolver_list and fastest_resolver with RecursiveResolver"
            )

        # The Queue will be registered in the selectors, but is never used
        # for the recursive resolver
        self.resolver_q: Queue = Queue()

        if isinstance(self.resolver, UpstreamResolver):
            assert resolver_list is not None

            if daemon_options.get("fastest_resolver.use"):
                self.resolver_daemon = daemon.FastestResolverDaemon(
                    resolver_list,
                    daemon_options["fastest_resolver.test_name"],
                    interval=daemon_options["fastest_resolver.interval"],
                    queue=self.resolver_q,
                )
                self.resolver_daemon.start()
                self.resolver.addr = self.resolver_q.get(True)
            else:
                if len(resolver_list) > 1:
                    raise ValueError(
                        "Unable to have more than one resolver when fastest_resolver.use is False"
                    )

                self.resolver_q.put(resolver_list[0])
                # Get the address
                self.resolver.addr = self.resolver_q.get()
                logging.info("Resolver address: %s", self.resolver.addr)

        # I removed the dump cache daemon because the cache was designed
        # to only be in-memory. If the cache was written to a file, all
        # the TimedItem's would expire, meaning the dump would be useless.

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
        if kwargs["storage.cache_path"] is not None:
            # TODO: Test this out
            p = Path(kwargs["storage.cache_path"]).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            storage.load_cache_from_file(p)

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

        if kwargs["resolver.recursive"]:
            resolver = RecursiveResolver()
        else:
            resolver = UpstreamResolver(("", 53))

        if kwargs["storage.preload_path"]:
            if not isinstance(resolver, RecursiveResolver):
                logging.warning(
                    "Preloading hosts without a recursive resolver doesn't bring significant speed improvements"
                )
            # TODO: Not implemented yey
            logging.warning(
                "This isn't implemented yet. ninjamar didn't realize that the host has to be added to the cache"
            )

        # HACK: This is what happens when it's 11 and I have to get the feature done
        if isinstance(kwargs["resolver.list"], list):
            resolver_list = [(addr, 53) for addr in kwargs["resolver.list"]]
        else:
            resolver_list = None

        if kwargs["resolver.add_system"]:
            resolver_list.append(get_dns_servers())

        logging.debug("Records: %s", storage)
        return cls(
            storage=storage,
            host=(kwargs["servers.host.host"], int(kwargs["servers.host.port"])),
            debug_shell_host=debug_shell_host,
            resolver=resolver,
            resolver_list=resolver_list,
            tls_host=tls_host,  # TODO: host vs addr
            ssl_key_path=kwargs["servers.tls.ssl_key"],
            ssl_cert_path=kwargs["servers.tls.ssl_cert"],
            max_workers=kwargs["all.max_workers"],
            daemon_options={
                k[8:]: v for k, v in kwargs.items() if k.startswith("daemon")
            },
            # daemon_options=kwargs["daemons"]
        )

    def cleanup(self) -> None:
        """Handle destroying the sockets."""
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

    def _handle_dns_query_udp(self, addr: tuple[str, int], query: bytes) -> None:
        """Handle a DNS query over UDP.

        Args:
            addr: Address of client.
            query: Incoming DNS query.
        """
        return ResponseHandler(
            storage=self.storage,
            resolver=self.resolver,
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
                        resolver=self.resolver,
                        tcp_conn=conn,
                    ).start(query)

    def _handle_dns_query_tls(self, conn: socket.socket) -> None:
        """Handle a DNS query over tls.

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
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            sys.stdin = sys.__stdin__
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

        # Update these devices when it's readable
        sockets = [
            # HACK-TYPING: Queue._reader is an implementation detail
            self.resolver_q._reader,  # type: ignore[attr-defined]
            self.udp_sock,
            self.tcp_sock,
        ]
        if self.use_tls:
            sockets.append(self.tls_sock)
        if self.use_debug_shell:
            sockets.append(self.debug_shell_sock)

        # Select a value when READ is available
        sel = selectors.DefaultSelector()
        for obj in sockets:
            sel.register(obj, selectors.EVENT_READ)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            try:
                while True:
                    try:
                        # FIXME: What should the timeout be? Does this fix the issue?
                        events = sel.select(timeout=0)
                        for key, mask in events:
                            obj = key.fileobj  # type: ignore[assignment]
                            if obj == self.udp_sock:
                                # TODO: Should receiving data be in the thread? (what)
                                query, addr = self.udp_sock.recvfrom(512)

                                future = executor.submit(
                                    self._handle_dns_query_udp, addr, query
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )
                            elif obj == self.tcp_sock:
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
                            elif obj == self.tls_sock:
                                conn, addr = self.tls_sock.accept()
                                conn.setblocking(False)
                                future = executor.submit(
                                    self._handle_dns_query_tls, conn
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )
                            elif obj == self.debug_shell_sock:
                                conn, addr = self.debug_shell_sock.accept()
                                future = executor.submit(
                                    self._handle_debug_shell_session, conn
                                )
                                future.add_done_callback(
                                    self._handle_thread_pool_completion
                                )

                            elif obj == self.resolver_q._reader: # type: ignore[attr-defined]
                                self.resolver.addr = self.resolver_q.get()
                                logging.info("Resolver address: %s", self.resolver.addr)

                    except KeyboardInterrupt:
                        # Don't want the except call here to be called, I want the one outside the while loop
                        raise KeyboardInterrupt
                    except Exception as e:
                        logging.error("Error", exc_info=True)

            except KeyboardInterrupt:
                logging.info("KeyboardInterrupt: Server shutting down")

                # Shutdown all threads
                # The with statement calls executor.shutdown(wait=True) already,
                # so this code could be modifed to have the try-except outside
                # of the with.
                executor.shutdown(wait=True)

                self.cleanup()

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
        except Exception as e:
            logging.error("Error", exc_info=True)
