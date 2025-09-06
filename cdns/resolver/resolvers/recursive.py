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
import selectors
import socket
import ssl
import struct
import sys
import threading
import logging
import ipdb

from collections import namedtuple
from enum import Enum
from typing import cast

from cdns.protocol import (DNSAdditional, DNSAnswer, DNSAuthority, DNSHeader,
                           DNSQuery, DNSQuestion, RTypes, auto_decode_label,
                           get_ip_mode_from_rtype, get_rtype_from_ip_mode,
                           unpack_all)
from cdns.resolver import forwarders

from .base import BaseResolver
from .upstream import UpstreamResolver
from cdns.resolver.forwarders.doh.http1 import HttpOneForwarder

# TODO: Load root server from url, write root server to disk and cache it
# ROOT_SERVERS = [p + ".ROOT-SERVERS.NET" for p in string.ascii_uppercase[:13]]
ROOT_SERVERS = [("198.41.0.4", 53)]

FORWARDERS = {
    "doh": forwarders.DoHForwarder,
    "tcp": forwarders.TCPForwarder,
    "tls": forwarders.TLSForwarder,
    "udp": forwarders.UDPForwarder,
}


class RecursiveResolver(BaseResolver):
    """Resolve a request recursively."""

    def __init__(
        self,
        forwarding_mode: str = "UDP",
        tls_endpoints: list[tuple[str, int]] | None = None,
        doh_endpoints: list[tuple[str, str, int]] | None = None,
    ) -> None:
        """Create an instance of RecursiveResolver."""

        # HACK: Specify forwarding_mode on a case-by-case basis using a dictionary.

        # TODO: Simplify structure here
        if tls_endpoints is None:
            self.tls_endpoints = []
        else:
            self.tls_endpoints = tls_endpoints
        if doh_endpoints is None:
            self.doh_endpoints = []
        else:
            self.doh_endpoints = doh_endpoints
        
        self.forwarding_mode = forwarding_mode

        # Activate the forwarder
        """
        self.forwarders_map = {
             "doh": forwarders.DoHForwarder(),
            "tcp": forwarders.TCPForwarder(),
            "tls": forwarders.TLSForwarder(),
            "udp": forwarders.UDPForwarder(),
        }
        """
        self.forwarders_map: dict[str, forwarders.BaseForwarder] = {
            k: v() for k, v in FORWARDERS.items()
        }

        # TODO: Errors raised in here do not propagate
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
        self, query: DNSQuery, server_addr: tuple[str, int], auto_detect_forwarder=True
    ) -> concurrent.futures.Future[DNSQuery]:
        """Resolve a query recursively.

        Args:
            query: Query to send.
            server_addr: Address of server.

        Returns:
            Future that fufils when there's a response.
        """
        #import dataclasses
        #logging.debug("Entering _resolve with query id=%s, state=%s", id(query), dataclasses.asdict(query))
        # Add auto detect forwarder
        future: concurrent.futures.Future[DNSQuery] = concurrent.futures.Future()
        def send():
            #logging.debug("Inside send with query id=%s, state=%s", id(query), dataclasses.asdict(query))
            try:
                # response = self.forwarder.forward(query, server_addr)
                # TODO: Auto detect server addr
                f = self._get_forwarder(query)
                # ipdb.set_trace()
                logging.debug("Here %s", query)
                # raise Exception("WHAT")
                response = f.forward(query, server_addr)
                response.add_done_callback(lambda f: self._resolve_done(f, query, future))
            except Exception as e:
                logging.debug("Error", exc_info=True)

        self.executor.submit(send)
        return future

    def _get_method(self, query: DNSQuery) -> str:
        if self.forwarding_mode == "auto":
            return query._method
        return self.forwarding_mode

    def _get_forwarder(self, query: DNSQuery) -> forwarders.BaseForwarder:
        return self.forwarders_map[self._get_method(query)]
        #return HttpOneForwarder()

    def get_server(self, query: DNSQuery) -> tuple[str, int]:
        # HACK: Make this function return a working endpoint. Also, make sure to
        # rotate these endpoints if a ping test fails for one of them.
        method = self._get_method(query)
        if method == "doh":
            return self.doh_endpoints[0]
        if method == "tls":
            return self.tls_endpoints[0]
        return ROOT_SERVERS[0]

    def send(
        self, query: DNSQuery, auto_detect_forwarder=True
    ) -> concurrent.futures.Future[DNSQuery]:
        """Send a query to the resolver.

        Args:
            query: Query in bytes.

        Returns:
            A future that fufils to a DNSQuery.
        """
        # TODO: In future take in DNS query, then query each question
        # TODO: Make a flowchart for this

        server_addr = self.get_server(query)

        # Even if we use TLS or DoH, there is no need to use an upstream resolver,
        # because the RecursiveResolver only follows links IF AVAILABLE. If the
        # response is given, then the resolver will not continue further

        # Server addr here is the culprit

        # TODO: Make sure only one question is being sent at a time
        # Detect ip_mode
        """
        t = query.questions[0].type_
        if t == RTypes.A:
            ip_size = 4
        elif t == RTypes.AAAA:
            ip_size = 16
        """
        return self._resolve(query, server_addr, auto_detect_forwarder)

    def cleanup(self):
        """Cleanup any loose ends."""
        for forwarder in self.forwarders_map.values():
            forwarder.cleanup()
