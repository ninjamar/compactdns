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

import concurrent.futures
import selectors
import socket
import threading
from typing import cast

from .protocol import (DNSAdditional, DNSAnswer, DNSAuthority, DNSHeader,
                           DNSQuery, DNSQuestion, RTypes, auto_decode_label,
                           get_ip_mode_from_rtype, get_rtype_from_ip_mode,
                           unpack_all)


class BaseForwarder:
    """Base forwarder class."""

    pass


class UdpForwarder(BaseForwarder):
    """Forwarder using UDP."""

    def __init__(self) -> None:
        """Create an instance of UDPForwarder."""

        # When we want to send, send the request, and add the socket to
        # pending_requests and selectors. When the socket can be read (checked)
        # in the thread, fufil the future.

        self.sel = selectors.DefaultSelector()
        self.pending_requests: dict[socket.socket, concurrent.futures.Future] = {}

        self.lock = threading.Lock()

        self.thread = threading.Thread(target=self._thread_handler)
        self.thread.daemon = True
        self.thread.start()

    def _thread_handler(self) -> None:
        """Handler for the thread that handles the response for forwarded
        queries."""

        # TODO: Add a way to use TLS for forwarding (use_secure_forwarder=True)

        while True:
            events = self.sel.select(timeout=1)  # TODO: Timeout
            with self.lock:
                for key, mask in events:
                    # TODO: Try except
                    sock = cast(socket.socket, key.fileobj)
                    # Don't error if no key
                    future = self.pending_requests.pop(sock, None)
                    if future:
                        try:
                            # TODO: Support responses larger longer than 512 using TCP
                            response, _ = sock.recvfrom(512)
                            future.set_result(response)
                        except Exception as e:
                            future.set_exception(e)
                        finally:
                            self.sel.unregister(sock)
                            sock.close()

    def forward(
        self, query: DNSQuery, addr: tuple[str, int]
    ) -> concurrent.futures.Future[bytes]:
        """Forward a DNS query to an address.

        Args:
            query: The DNS query to forward.
            addr: Address of the server.

        Returns:
            The response from the forwarding server.
        """
        # TODO: If using TCP, use a different socket (can be same, even though overhead -- much less tcp requests)
        # TODO: If TC, use either TLS or UDP with multiple packets
        # TODO: TC flag?

        # new socket for each request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        future: concurrent.futures.Future = concurrent.futures.Future()

        # TODO: The bottleneck
        try:
            sock.sendto(query.pack(), addr)
            with self.lock:
                # Add a selector, and when it is ready, read from pending_requests
                self.sel.register(sock, selectors.EVENT_READ)
                self.pending_requests[sock] = future

        except Exception as e:
            future.set_exception(e)
            sock.close()
        return future

    def cleanup(self):
        for sock in self.pending_requests.keys():
            sock.close()


class BaseResolver:
    """Base class for resolvers."""

    def send(self, query: DNSQuery) -> concurrent.futures.Future[DNSQuery]:
        raise NotImplementedError

    def cleanup(self):
        raise NotImplementedError


class UpstreamResolver(BaseResolver):
    """A class to resolve from upstream."""

    def __init__(self, addr: tuple[str, int]) -> None:
        """Create an instance of UpstreamResolver.

        Args:
            addr: Address of the upstream.
        """
        self.addr = addr
        self.forwarder = UdpForwarder()

    def send(self, query: DNSQuery) -> concurrent.futures.Future[DNSQuery]:
        """Send a query to the upstream.

        Args:
            query: Query to send.

        Returns:
            The future fufilling the query.
        """
        ret: concurrent.futures.Future[DNSQuery] = concurrent.futures.Future()

        f = self.forwarder.forward(query, self.addr)
        f.add_done_callback(
            lambda s: ret.set_result(unpack_all(s.result()))
        )  # ret.result = unpack_all(s.result)

        return ret

    def cleanup(self):
        self.forwarder.cleanup()


def _do_answers_match_questions(questions, answers):
    for q, a in zip(questions, answers):
        if q.decoded_name != a.decoded_name:
            return False
    return True


# TODO: Load root server from url, write root server to disk and cache it
# ROOT_SERVERS = [p + ".ROOT-SERVERS.NET" for p in string.ascii_uppercase[:13]]
ROOT_SERVERS = [("198.41.0.4", 53)]


class RecursiveResolver(BaseResolver):
    """Resolve a request recursively."""

    def __init__(self) -> None:
        """Create an instance of RecursiveResolver."""
        self.forwarder = UdpForwarder()
        self.executor = concurrent.futures.ThreadPoolExecutor()
        """Server = root server send request to server (enable timeout) receive
        response parse response if the response has ip address of domain return
        response."""

    def _find_nameserver(
        self,
        authorities: list[DNSAuthority],
        additionals: list[DNSAdditional],
        query: DNSQuery,
        to_future: concurrent.futures.Future[DNSQuery],
    ) -> None:
        """Find a nameservers.

        Args:
            authorities: Authorities.
            additionals: Additionals.
            query: Query.
            to_future: Future to forward off to.
        """
        # Match authorities and additionals to get IP address. Right now it's fine
        # to just get the first IP address if there is one. If there isn't one, recursively
        # resolve the first name server (AAH MORE LOOPS)
        # self.ip_fallback_list = [x.decoded_rdata for x in additionals if x.rdlength == ip_size]
        # ip = self.ip_fallback_list[0]
        ip = next((x.decoded_rdata for x in additionals if x.rdlength == 4), None)
        # ip = next((x.decoded_rdata for x in additionals if x.rdlength == ip_size), None)
        if ip:
            self._post_nameserver_found(ip, query, to_future)
        else:
            # Resolve nameserver
            nameserver = authorities[0].decoded_rdata

            q = DNSQuery(DNSHeader(), [DNSQuestion(decoded_name=nameserver)])
            # future = self._resolve(query,)
            # Get the IP addresses of the nameservers
            # future = self.send(q, 4)
            future = self.send(q)

            def callback(f: concurrent.futures.Future[DNSQuery]):
                nameservers = f.result()

                # Once we have the IP addresses. The answers contain the IP,
                # but the function expects the additionals section to contain
                # them. So, we pass the answers as the additionals. This works
                # because DNSAnswer, DNSAuthority, and DNSAdditional are all
                # identical.
                self._find_nameserver([], nameservers.answers, query, to_future)  # type: ignore[arg-type]

            future.add_done_callback(callback)

    def _post_nameserver_found(
        self,
        nameserver: str,
        query: DNSQuery,
        to_future: concurrent.futures.Future[DNSQuery],
    ) -> concurrent.futures.Future:
        """Callback after nameservers are found.

        Args:
            nameserver: IP address of nameserver.
            query: Query to send.
            to_future: The parent future.

        Returns:
            The new future (not sure why it returns, but it does)
        """
        new_future = self._resolve(query, (nameserver, 53))
        new_future.add_done_callback(lambda f: to_future.set_result(f.result()))
        return new_future

    def _resolve_done(
        self,
        recv_future: concurrent.futures.Future[bytes],
        query: DNSQuery,
        to_future: concurrent.futures.Future[DNSQuery],
    ) -> None:
        """Called after _resolve.

        Args:
            recv_future: Future received
            query: Query.
            to_future: New future.
        """
        response = recv_future.result()
        r = unpack_all(response)

        # answers, authorities, additionals = _filter_extra(answers)

        if r.answers:  # and _do_answers_match_questions(query.questions, r.answers):
            # if _do_answers_match_questions(query.questions, r.answers):
            #   pass
            # TODO: I think the problem is that at some point, answers can contain
            # the stuff supposed to be in authorities. Instead of checking if
            # answers, we should check if the answers match the original questions
            # The problem is that these questions are never stored. This means
            # that we need to refactor the code to pack the questions inside
            # RecursiveResolver.send(). And we also need to rework response.py

            # if r.answers
            # Make a new query without any fluff
            r.authorities = []
            r.additionals = []
            to_future.set_result(r)
        elif r.authorities:
            # GET IPV4 record
            # This function executes rest of code
            self._find_nameserver(r.authorities, r.additionals, query, to_future)
        else:
            # TODO: DO authorities and additionals always go together?

            # If there are no answers and authorities (authorities and additionals most likely go together),
            # then return an error
            error_query = DNSQuery(
                DNSHeader(id_=r.header.id_, rcode=0), questions=r.questions, answers=[]
            )

            to_future.set_result(error_query)

    def _resolve(
        self, query: DNSQuery, server_addr: tuple[str, int]
    ) -> concurrent.futures.Future[DNSQuery]:
        """Resolve a query recursively.

        Args:
            query: Query to send.
            server_addr: Address of server.

        Returns:
            Future that fufils when there's a response.
        """
        future: concurrent.futures.Future[DNSQuery] = concurrent.futures.Future()

        def send():
            response = self.forwarder.forward(query, server_addr)
            response.add_done_callback(lambda f: self._resolve_done(f, query, future))

        self.executor.submit(send)
        return future

    def send(self, query: DNSQuery) -> concurrent.futures.Future[DNSQuery]:
        """Send a query to the resolver.

        Args:
            query: Query in bytes.

        Returns:
            A future that fufils to a DNSQuery.
        """
        # TODO: In future take in DNS query, then query each question
        # TODO: Make a flowchart for this

        server_addr = ROOT_SERVERS[0]  # TODO: Could be random

        # TODO: Make sure only one question is being sent at a time
        # Detect ip_mode

        t = query.questions[0].type_
        if t == RTypes.A:
            ip_size = 4
        elif t == RTypes.AAAA:
            ip_size = 16

        return self._resolve(query, server_addr)

    def cleanup(self):
        """Cleanup any loose ends."""
        self.forwarder.cleanup()
