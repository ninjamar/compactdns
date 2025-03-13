import concurrent.futures
import dataclasses
import itertools
import logging
import selectors
import socket
import struct
from typing import Callable

from .protocol import (DNSAnswer, DNSHeader, DNSQuestion, RTypes,
                       auto_decode_label, auto_encode_label,
                       pack_all_compressed, unpack_all)
from .storage import RecordStorage

# TODO: Send back and check TC flag


class ResponseHandler:
    """
    A class to make a DNS response.
    """

    def __init__(
        self,
        storage: RecordStorage,
        forwarder: Callable[[bytes], concurrent.futures.Future[bytes]],
        udp_sock: socket.socket | None = None,
        udp_addr: tuple[str, int] | None = None,
        tcp_conn: socket.socket | None = None,
    ) -> None:
        """
        Create a ResponseHandler instance.
        Use with either UDP or TCP.

        Args:
            storage: Storage.
            forwarder: Function that forwards DNS queries.
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

        self.buf = b""  # Response buffer

        self.storage = storage
        self.forwarder = forwarder

        # Header and qustions from the initial buffer
        self.buf_header: DNSHeader | None = None
        self.buf_questions: list[DNSQuestion] = []

        self.new_header: DNSHeader | None = None
        self.new_questions: list[DNSQuestion] = []

        self.resp_header: DNSHeader | None = None
        self.resp_questions: list[DNSQuestion] = []
        self.resp_answers: list[DNSAnswer] = []

        self.question_index_intercepted: list[tuple[int, list[DNSAnswer]]] = []
        self.question_answers: list[DNSAnswer] = []

    def start(self, buf) -> None:
        """
        Unpack a buffer, then process it.

        Args:
            buf: Buffer to unpack.
        """
        success = self._receive(buf)
        if success:
            self._process()

    def _receive(self, buf: bytes) -> bool:
        """
        Receive a buffer, unpacking it.

        Args:
            buf: Buffer to unpack.
        """
        # Receive header and questions
        try:
            self.buf_header, self.buf_questions, _ = unpack_all(buf)
            logging.debug("Received query: %s, %s", self.buf_header, self.buf_questions)
            return True
        except (struct.error, IndexError) as e:
            # raise e
            logging.error("Unable to unpack DNS query")
            return False

    def _process(self) -> None:
        """
        Start the process.
        """
        if self.buf_header is None:
            raise Exception("Buffer header can't be empty")
        
        self.new_header = dataclasses.replace(self.buf_header)

        # Remove intercepted sites, so it doesn't get forwarded
        # Remove cached sites, so it doesn't get forwarded
        for idx, question in enumerate(self.buf_questions):
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
                    rdata = auto_encode_label(data)
                    answers.append(
                        DNSAnswer(
                            decoded_name=record_domain,
                            type_=int(type_),
                            ttl=int(ttl),
                            rdata=rdata,
                            rdlength=len(rdata),
                        )
                    )

                # self.question_answers.append(*answers)
                self.question_answers.extend(answers)
                self.question_index_intercepted.append((idx, answers))
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
            future.add_done_callback(self._forwarding_done_handler)
        else:
            self.resp_header = self.new_header
            self.resp_header.qr = 1
            self.resp_questions = self.new_questions
            self.resp_answers = []

            self._post_process()

    def _forwarding_done_handler(self, future: concurrent.futures.Future[bytes]) -> None:
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

        self._post_process()

    def _post_process(self) -> None:
        """
        Automatically called after self.process.
        """
        if self.buf_header is None:
            raise Exception
        # We could also make a copy of self.resp_header, but it doesn't matter
        # Make a new header
        self.resp_header = DNSHeader(
            id_=self.buf_header.id_,  # Same id
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
            question = self.buf_questions[idx]
            self.resp_questions.insert(idx, question)
            self.resp_answers[idx:idx] = answers

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

        if len(self.resp_answers) > 0:
            # self.question_index_intercepted

            cache_answers = {
                decoded_name: list(groups)  # Key to groups
                for decoded_name, groups in itertools.groupby(  # Group consequtive items with the same key together
                    sorted(
                        self.resp_answers, key=lambda q: q.decoded_name
                    ),  # Sort resp_answers by the decoded name
                    key=lambda q: q.decoded_name,
                )
            }
            for question in self.resp_questions:
                answers = cache_answers[question.decoded_name]
                # Cache the rdata

                # TODO: Why is publicsuffix2 faster than tldextractor
                # print([answer for answer in answers])
                values = [
                    (auto_decode_label(answer.rdata), int(answer.ttl))
                    for answer in answers
                    if answer.type_ == RTypes.A
                    or answer.type_
                    == RTypes.AAAA  # HACK: This is a CRITICAL temporary fix
                ]

                # HACK: This fix only caches A and AAAA records. Apparently CNAME records
                # have some encoded labels. This would require some large changes to be made.

                # TODO:  macos system service/daemon -- use processes -- configure cores and workers -- figure out what to do with RTYPES (maybe enum or smtn)
                # base_domain = get_base_domain(question.decoded_name)
                self.storage.cache.set_record(
                    name=question.decoded_name,
                    record_type=question.type_,
                    values=values,
                    overwrite=True,
                )

        self.buf = pack_all_compressed(
            self.resp_header, self.resp_questions, self.resp_answers
        )

        # TODO: This isn't sufficient
        # Need to also be able to receive packets of more than 512 bytes using tcp
        if self.udp_sock and len(self.buf) > 512:
            # TODO: Use array indexing to set TC rather than reconstructing the packet
            self.resp_header.tc = 1
            self.buf = pack_all_compressed(
                self.resp_header, self.resp_questions, self.resp_answers
            )[:512]

        self._send()

    def _send(self) -> None:
        """
        Send a DNS query back.
        """
        # buf = pack_all_compressed(
        #     self.resp_header, self.resp_questions, self.resp_answers
        # )

        if self.udp_sock and self.udp_addr:
            # Lock is unnecessary here since .sendto is thread safe (UDP is also connectionless)

            self.udp_sock.sendto(self.buf, self.udp_addr)
        elif self.tcp_conn:
            buf_len = struct.pack("!H", len(self.buf))

            sel = selectors.DefaultSelector()
            sel.register(self.tcp_conn, selectors.EVENT_WRITE)

            # Block and wait for the socket to be ready (only happens once)
            sel.select(timeout=0.1)
            try:
                self.tcp_conn.sendall(buf_len + self.buf)
            finally:
                self.tcp_conn.close()
                sel.unregister(self.tcp_conn)
                logging.debug("Closed TCP connection")
