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
# SOFTWARE.

import concurrent.futures
import dataclasses
import itertools
import logging
import selectors
import socket
import ssl
import struct
import sys
import threading
from typing import Callable
from .protocol import DNSAnswer, DNSHeader, DNSQuestion, pack_all_compressed, unpack_all
from .storage import Blocklist, TimedCache

MAX_WORKERS = 1000


class ServerManager:
    """A class to store a server session."""

    def __init__(
        self,
        host: tuple[str, int],
        tls_host: tuple[str, int] | None,
        ssl_key_path: str | None,
        ssl_cert_path: str | None,
        resolver: tuple[str, int],
        blocklist: Blocklist,
        max_cache_length: int,
    ) -> None:
        """Create a ServerManager instance.

        Args:
            host: Host and port of server for UDP and TCP.
            tls_host: Host and port of server for DNS over TLS.
            ssl_key_path: Path to SSL key file.
            ssl_cert_path: Path to SSL cert file.
            resolver: Host and port of resolver.
            blocklist: Blocklist of sites.
        """
        self.host = host
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

        self.blocklist = blocklist

        self.cache = TimedCache(max_length=max_cache_length)

        if len(self.blocklist) > max_cache_length:  # FIXME: > or >=? can't decide
            logging.warning(
                "The blocklist has %i items, the max cache length is %i",
                len(self.blocklist),
                max_cache_length,
            )

        # FIXME: This probably doesn't have much of an advantage
        # TODO: If we get a cached answer, should the ttl in the TimedCache be updated?
        # Cache individual hosts that don't contain any special syntax
        # Caching is for when type_ and class_ is 1
        # Use _host rather than host, since host is an argument to this function
        for _host in self.blocklist.normal.keys():
            self.cache.set(
                DNSQuestion(decoded_name=_host, type_=1, class_=1),
                DNSAnswer(
                    decoded_name=_host,
                    type_=1,
                    class_=1,
                    ttl=int(self.blocklist.normal[_host].ttl),  # float to int
                    rdlength=4,
                    # inet_aton encodes a ip address into bytes
                    rdata=socket.inet_aton(self.blocklist.normal[_host].ip),
                ),
                # FIXME: Fix (Why is this label here?)
                self.blocklist.normal[_host].ttl,
            )

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
        ResponseHandlerManager(
            blocklist=self.blocklist,
            cache=self.cache,
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
                    ResponseHandlerManager(
                        blocklist=self.blocklist,
                        cache=self.cache,
                        forwarder=self.forward_dns_query,
                        tcp_conn=conn,
                    ).start(query)

                    return

    def _handle_dns_query_tls(self, conn: socket.socket) -> None:
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

        return self._handle_dns_query_tcp(tls)

    def start(self) -> None:
        """Start the server."""
        # TODO: Configure max workers

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

        sockets = [self.udp_sock, self.tcp_sock]
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


# TODO: Better name
class ResponseHandlerManager:
    """
    A class to make a DNS response.
    """

    def __init__(
        self,
        blocklist: Blocklist,
        cache: TimedCache,
        forwarder: Callable[[bytes], concurrent.futures.Future[bytes]],
        udp_sock: socket.socket = None,
        udp_addr: tuple[str, int] = None,
        tcp_conn: socket.socket = None,
    ) -> None:
        """
        Create a ResponseHandlerManager instance.
        Use with either UDP or TCP.

        Args:
            blocklist: Blocklist to use
            cache: Cache.
            forwarder: Function that forwards DNS queries.
            udp_sock: UDP socket. Defaults to None.
            udp_addr: UDP address. Defaults to None.
            tcp_conn: TCP connection.. Defaults to None.

        Raises:
            TypeError: If UDP or TCP is not specified.
        """
        self.udp_sock = None
        self.udp_addr = None
        self.tcp_conn = None

        if udp_sock and udp_addr:
            self.udp_sock = udp_sock
            self.udp_addr = udp_addr
        elif tcp_conn:
            self.tcp_conn = tcp_conn
        else:
            raise TypeError("Must pass either UDP socket or TCP connection")

        self.blocklist = blocklist
        self.cache = cache
        self.forwarder = forwarder

        # Header and qustions from the initial buffer
        self.buf_header = None
        self.buf_questions = []

        self.new_header = None
        self.new_questions = []

        self.resp_header = None
        self.resp_questions = []
        self.resp_answers = []

        self.question_index_blocked = []
        self.question_index_cached = []

    def start(self, buf) -> None:
        """
        Unpack a buffer, then process it.

        Args:
            buf: Buffer to unpack.
        """
        self.receive(buf)
        self.process()

    def receive(self, buf: bytes) -> None:
        """
        Receive a buffer, unpacking it.

        Args:
            buf: Buffer to unpack.
        """
        # Receive header and questions
        self.buf_header, self.buf_questions, _ = unpack_all(buf)
        logging.debug("Received query: %s, %s", self.buf_header, self.buf_questions)

    def process(self) -> None:
        """
        Start the process.
        """
        self.new_header = dataclasses.replace(self.buf_header)

        # Remove blocked sites, so it doesn't get forwarded
        # Remove cached sites, so it doesn't get forwarded
        for idx, question in enumerate(self.buf_questions):
            if question in self.cache:
                self.question_index_cached.append(idx)
            # Use file matching syntax to detect block
            elif question_index_match := self.blocklist.get_name_block(
                question.decoded_name
            ):
                self.question_index_blocked.append((idx, question_index_match))
            else:
                self.new_questions.append(question)

                # Set new qdcount for forwarded header
        self.new_header.qdcount = len(self.new_questions)
        logging.debug(
            "New header %s, new questions %s", self.new_header, self.new_questions
        )

        if self.new_header.qdcount > 0:
            # Process header, questions
            # Repack data
            send = pack_all_compressed(self.new_header, self.new_questions)
            future = self.forwarder(send)
            future.add_done_callback(self.forwarding_done_handler)
        else:
            self.resp_header = self.new_header
            self.resp_header.qr = 1
            self.resp_questions = self.new_questions
            self.resp_answers = []

            self.post_process()

    def forwarding_done_handler(self, future: concurrent.futures.Future[bytes]) -> None:
        """
        Callback when self.forwarder is complete.

        Args:
            future: Future from self.forwarder.
        """
        self.resp_header, self.resp_questions, self.resp_answers = unpack_all(
            future.result()
        )
        if len(self.resp_answers) == 0:
            self.resp_answers = []

        self.post_process()

    def post_process(self) -> None:
        """
        Automatically called after self.process.
        """
        # Disable the recursion flag for cached or blocked queries
        # I'm not sure how much this actually works
        # https://serverfault.com/a/729121
        if len(self.question_index_cached) > 0 or len(self.question_index_blocked) > 0:
            self.resp_header.rd = 0
            self.resp_header.ra = 0

        # Add the cached questions to the response, keeping the position
        for idx in self.question_index_cached:
            question = self.buf_questions[idx]
            self.resp_questions.insert(idx, question)

            # https://stackoverflow.com/a/7376026/21322342
            self.resp_answers[idx:idx] = self.cache.get_and_renew_ttl(question)

        # Add the blocked questions to the response, keeping the position
        for idx, match in self.question_index_blocked:
            question = self.buf_questions[idx]
            # Fake answer
            answer = DNSAnswer(
                decoded_name=question.decoded_name,
                type_=question.type_,
                class_=question.type_,
                ttl=int(self.blocklist[match].ttl),
                rdlength=4,
                # inet_aton encodes a ip address into bytes
                rdata=socket.inet_aton(self.blocklist[match].ip),
            )

            # Insert the questions and answer to the correct spot
            self.resp_questions.insert(idx, question)
            self.resp_answers.insert(idx, answer)

        # Update the header's question and answer count
        self.resp_header.qdcount = len(self.resp_questions)
        self.resp_header.ancount = len(self.resp_answers)

        # TODO: Go after mkve
        logging.debug(
            "Sending query back, %s, %s, %s",
            self.resp_header,
            self.resp_questions,
            self.resp_answers,
        )

        cache_questions = sorted(self.buf_questions, key=lambda q: q.decoded_name)

        # Store multiple answers for a questions
        cache_answers = {
            decoded_name: list(groups)  # Key to groups
            for decoded_name, groups in itertools.groupby(  # Group consequtive items with the same key together
                sorted(
                    self.resp_answers, key=lambda q: q.decoded_name
                ),  # Sort resp_answers by the decoded name
                key=lambda q: q.decoded_name,
            )
        }

        for cache_question in cache_questions:
            if cache_question not in self.cache:
                answers = cache_answers[cache_question.decoded_name]
                self.cache.set(
                    cache_question,
                    answers,
                    answers[
                        0
                    ].ttl,  # TODO: I store one question to many answers with one ttl
                )
        # Since we have a new response, cache it, using the original question and new answer

        self.send()

    def send(self) -> None:
        """
        Send a DNS query back.
        """
        buf = pack_all_compressed(
            self.resp_header, self.resp_questions, self.resp_answers
        )
        buf_len = struct.pack("!H", len(buf))

        if self.udp_sock:
            # Lock is unnecessary here since .sendto is thread safe (UDP is also connectionless)

            self.udp_sock.sendto(buf, self.udp_addr)
        elif self.tcp_conn:
            sel = selectors.DefaultSelector()
            sel.register(self.tcp_conn, selectors.EVENT_WRITE)

            # Block and wait for the socket to be ready (only happens once)
            sel.select(timeout=0.1)
            try:
                self.tcp_conn.sendall(buf_len + buf)
            finally:
                self.tcp_conn.close()
                sel.unregister(self.tcp_conn)
                logging.debug("Closed TCP connection")
