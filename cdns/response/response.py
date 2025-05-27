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
import dataclasses
import itertools
import logging
import selectors
import socket
import struct
from typing import Callable

from cdns.protocol import (DNSAnswer, DNSHeader, DNSQuery, DNSQuestion, RTypes,
                       auto_decode_label, auto_encode_label, unpack_all)
from cdns.resolver import BaseResolver, RecursiveResolver
from cdns.storage import RecordStorage

from cdns.lcb import LCBMethods

# TODO: Send back and check TC flag


# TODO: Clear TODO's -- this function below isn't being used
def _add_to_cache(cache, questions, answers):
    # For preloading
    # TODO: Implement
    # TODO: Document all changes across everything
    # TODO: Just ran mypy and it fails, so make it pass
    # TODO: Work on tests (hyperion or smtn)
    pass

# TODO: Override login to use broadcast system
class BaseResponseHandler(LCBMethods):
    """A class to make a DNS response."""

    def __init__(
        self,
        storage: RecordStorage,
        resolver: BaseResolver,
        udp_sock: socket.socket | None = None,
        udp_addr: tuple[str, int] | None = None,
        tcp_conn: socket.socket | None = None,
    ) -> None:
        """Create a ResponseHandler instance. Use with either UDP or TCP.

        Args:
            storage: Storage.
            resolver: Resolver class.
            udp_sock: UDP socket. Defaults to None.
            udp_addr: UDP address. Defaults to None.
            tcp_conn: TCP connection. Defaults to None.

        Raises:
            TypeError: If UDP or TCP is not specified.
        """
        self.udp_sock: socket.socket | None = None
        self.udp_addr: tuple[str, int] | None = None
        self.tcp_conn: socket.socket | None = None

        if udp_sock and udp_addr:
            self.udp_sock = udp_sock
            self.udp_addr = udp_addr
        elif tcp_conn:
            self.tcp_conn = tcp_conn
        else:
            raise TypeError("Must pass either UDP socket or TCP connection")

        self.bsend = b""  # TODO: Not to be confused with self.buf

        self.storage = storage
        self.resolver = resolver

        self.buf = DNSQuery()
        self.new = DNSQuery()
        self.resp = DNSQuery()
        """# Header and qustions from the initial buffer self.buf_header:
        DNSHeader | None = None self.buf_questions: list[DNSQuestion] = []

        self.new_header: DNSHeader | None = None self.new_questions:
        list[DNSQuestion] = []

        self.resp_header: DNSHeader | None = None self.resp_questions:
        list[DNSQuestion] = [] self.resp_answers: list[DNSAnswer] = []
        """
        self.question_index_intercepted: list[tuple[int, list[DNSAnswer]]] = []
        self.question_answers: list[DNSAnswer] = []

    def start(self, buf) -> None:
        """Unpack a buffer, then process it.

        Args:
            buf: Buffer to unpack.
        """

        self.lcb.start()

        success = self._receive(buf)
        if success:
            self._process()

    def _receive(self, buf: bytes) -> bool:
        """Receive a buffer, unpacking it.

        Args:
            buf: Buffer to unpack.
        """
        # Receive header and questions
        try:
            # self.buf_header, self.buf_questions, _ = unpack_all(buf)
            self.buf = unpack_all(buf)
            logging.debug("Received query: %s, %s", self.buf.header, self.buf.questions)
            return True
        except (struct.error, IndexError) as e:
            # raise e
            logging.error("Unable to unpack DNS query")
            return False

    def _process(self) -> None:
        """Start the process."""
        if self.buf.header is None:
            raise Exception("Buffer header can't be empty")

        self.new = DNSQuery(dataclasses.replace(self.buf.header))

        # Remove intercepted sites, so it doesn't get forwarded
        # Remove cached sites, so it doesn't get forwarded
        for idx, question in enumerate(self.buf.questions):
            # TODO: Find root domain
            type_ = question.type_
            record_domain = question.decoded_name
            if type_ == RTypes.SOA or type_ == RTypes.MX:
                raise NotImplementedError("SOA and MX records aren't supported yet")

            records = self.storage.get_record(type_=type_, record_domain=record_domain)

            if len(records) > 0:
                answers = []
                for record in records:
                    data, ttl = record
                    # rdata = auto_encode_label(data)
                    answers.append(
                        DNSAnswer(
                            decoded_name=record_domain,
                            type_=int(type_),
                            ttl=int(ttl),
                            decoded_rdata=data,
                            # rdlength=len(rdata), # -- length is already specified when packed
                        )
                    )

                # self.question_answers.append(*answers)
                self.question_answers.extend(answers)
                self.question_index_intercepted.append((idx, answers))
            else:
                self.new.questions.append(question)

        # Set new qdcount for forwarded header
        self.new.header.qdcount = len(self.new.questions)
        logging.debug(
            "New header %s, new questions %s", self.new.header, self.new.questions
        )
        if self.new.header.qdcount > 0:
            # Process header, questions
            # Repack data
            # to_send = self.new.pack()

            # TODO: Should this be exposed?
            # future = self.resolver.send(to_send, ip_mode)
            future = self.resolver.send(self.new)
            # send = pack_all_compressed(self.new_header, self.new_questions)
            # future = self.forwarder(send)
            future.add_done_callback(self._forwarding_done_handler)
        else:
            self.resp = DNSQuery(self.new.header, self.new.questions)
            self.resp.header.qr = 1

            self._post_process()

    def _forwarding_done_handler(
        self, future: concurrent.futures.Future[DNSQuery]
    ) -> None:
        """Callback when self.forwarder is complete.

        Args:
            future: Future from self.forwarder.
        """
        # self.resp = unpack_all(future.result())
        self.resp = future.result()

        # if len(self.resp.answers) == 0:
        #    self.resp.answers = []

        self._post_process()

    def _post_process(self) -> None:
        """Automatically called after self.process."""
        if self.buf.header is None:
            raise ValueError("buf_header cannot be None")
        # We could also make a copy of self.resp_header, but it doesn't matter
        # Make a new header
        self.resp.header = DNSHeader(
            id_=self.buf.header.id_,  # Same id
            qr=1,  # Response
            # These flags are all 0
            opcode=0,
            aa=0,
            tc=0,
            # No recursion
            rd=0,
            ra=0,
            z=0,  # TODO: Make constant
        )

        # Add the intercepted questions to the response, keeping the position
        for idx, answers in self.question_index_intercepted:
            question = self.buf.questions[idx]
            self.resp.questions.insert(idx, question)
            self.resp.answers[idx:idx] = answers

        # Update the header's question and answer count
        self.resp.header.qdcount = len(self.resp.questions)
        self.resp.header.ancount = len(self.resp.answers)

        # TODO: Go after mkve
        logging.debug(
            "Sending query back, %s, %s, %s",
            self.resp.header,
            self.resp.questions,
            self.resp.answers,
        )

        if len(self.resp.answers) > 0:
            # self.question_index_intercepted

            cache_answers = {
                decoded_name: list(groups)  # Key to groups
                for decoded_name, groups in itertools.groupby(  # Group consequtive items with the same key together
                    sorted(
                        self.resp.answers, key=lambda q: q.decoded_name
                    ),  # Sort resp_answers by the decoded name
                    key=lambda q: q.decoded_name,
                )
            }
            for question in self.resp.questions:
                answers = cache_answers[question.decoded_name]
                # Cache the rdata

                # TODO: Why is publicsuffix2 faster than tldextractor
                values = [
                    (answer.decoded_rdata, int(answer.ttl))
                    # (auto_decode_label(answer.rdata), int(answer.ttl))
                    for answer in answers
                    if answer.type_ == RTypes.A
                    or answer.type_
                    == RTypes.AAAA  # HACK: This is a CRITICAL temporary fix
                ]

                # Make sure we have values to cache.
                # HACK: Do a quick lookup to make sure that the answers should be cached.
                # An answer should only be cached if it isn't in the local storage. This
                # temporary fix does another lookup on the domain for the records. TODO:
                # in the future, the lookup should be stored from earlier.
                if len(values) > 0 and not self.storage.get_record(
                    record_domain=answers[0].decoded_name, type_=answers[0].type_
                ):
                    # print("setting", values, RTypes.A.i)
                    # HACK: This fix only caches A and AAAA records. Apparently CNAME records
                    # have some encoded labels. This would require some large changes to be made.

                    # TODO:  macos system service/daemon -- use processes -- configure cores and workers -- figure out what to do with RTYPES (maybe enum or smtn)
                    # base_domain = get_base_domain(question.decoded_name)
                    # print("SETTING VALUES", values)
                    self.storage.cache.set_record(
                        name=question.decoded_name,
                        record_type=question.type_,
                        values=values,
                        overwrite=True,
                    )
        # self.buf = pack_all_compressed(
        #    self.resp_header, self.resp_questions, self.resp_answers
        # )

        try:
            self.bsend = self.resp.pack()
        except:
            logging.error("%s %s", self.buf, self.resp)
            # print(self.buf, self.resp)
            # raise Exception
        # print(self.buf)

        # TODO: This isn't sufficient
        # Need to also be able to receive packets of more than 512 bytes using tcp
        if self.udp_sock and len(self.bsend) > 512:
            # TODO: Use array indexing to set TC rather than reconstructing the packet
            self.resp.header.tc = 1
            self.bsend = self.resp.pack()[:512]
            # self.buf = pack_all_compressed(
            #    self.resp_header, self.resp_questions, self.resp_answers
            # )[:512]

        self._send()

    def _send(self) -> None:
        """Send a DNS query back."""
        # buf = pack_all_compressed(
        #     self.resp_header, self.resp_questions, self.resp_answers
        # )

        if self.udp_sock and self.udp_addr:
            # Lock is unnecessary here since .sendto is thread safe (UDP is also connectionless)
            # TODO: Release timer
            self.udp_sock.sendto(self.bsend, self.udp_addr)
            self.lcb.end()
        elif self.tcp_conn:
            buf_len = struct.pack("!H", len(self.bsend))

            sel = selectors.DefaultSelector()
            sel.register(self.tcp_conn, selectors.EVENT_WRITE)

            # Block and wait for the socket to be ready (only happens once)
            sel.select(timeout=0.1)
            try:
                self.tcp_conn.sendall(buf_len + self.bsend)
                self.lcb.end()
            finally:
                self.tcp_conn.close()
                sel.unregister(self.tcp_conn)
                logging.debug("Closed TCP connection")
        
        


def preload_hosts(
    hosts: list[str], storage: RecordStorage, resolver: BaseResolver
) -> None:
    for host in hosts:
        # Monkeypatch the buffer, ignoring the fake socket connection
        r = BaseResponseHandler(storage=storage, resolver=resolver, tcp_conn=True)  # type: ignore

        # Don't send any data back
        r._send = lambda: None  # type: ignore

        r.buf = DNSQuery(
            header=DNSHeader(qdcount=1), questions=[DNSQuestion(decoded_name=host)]
        )
        r._process()
