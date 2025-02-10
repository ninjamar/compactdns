#!/usr/bin/env python3

# dns-server
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
"""This module, CompactDNS is a small, portable DNS server with support for
blocking certain hostnames.

Requires a minimum python version of 3.11.

$ python cdns.py -h
usage: cdns.py [-h] --host HOST --resolver RESOLVER [--blocklist [BLOCKLIST ...]]
               [--loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
               [--mode {normal,threaded}] [--ttl TTL]

A simple forwarding DNS server

options:
  -h, --help            show this help message and exit
  --host HOST, -a HOST  The host address in the format of a.b.c.d:port
  --resolver RESOLVER, -r RESOLVER
                        The resolver address in the format of a.b.c.d:port
  --blocklist [BLOCKLIST ...], -b [BLOCKLIST ...]
                        Path to file containing blocklist
  --loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}, -l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Provide information about the logging level (default = info)
  --mode {normal,threaded}, -m {normal,threaded}
                        Mode to run server (default = threaded)
  --ttl TTL             Default TTL for blocked hosts

See example-blocklists/ for example blocklists.
"""

import argparse
import concurrent.futures
import dataclasses
import fnmatch
import functools
import json
import logging
import os.path
import socket
import struct
import threading
import time
import tomllib
from collections.abc import KeysView
from typing import Any, Hashable, NamedTuple

# TODO: Document the archictecture (comments)
# TODO: Ensure all code is right (via tests)

# TODO: Document this code more
# TODO: Document and organize handle_dns_query

# TODO: Max size on TimedCache

# TODO: Turn this into a module in a directory
# TODO: When this is a module, maybe allow some DNS tunneling and messaging stuff?

# TODO: Benchmark via profiler.py

# TODO: Configuration file format other than fromfile_prefix_chars

# TODO: Verbose mode (better logging stuff)
# TODO: Forward logging to logging process (via multiprocessing)

# TODO: Add timeout to ThreadPoolExecutor
# TODO: Make sure the threading part of the server is working

# TODO: Add contributing guide to README before 1.0.0
# TODO: Once version 1.0.0 is released, upload this project to PyPi

# TODO: Support -b FILE FILE FILE and -b FILE -b FILE -b FILE

FNMATCH_CHARS = "*?[]!"


class TimedCache:
    """A dictionary, with expiring keys."""

    def __init__(self) -> None:
        """Create a TimedCache instance."""
        self.data: dict[Hashable, tuple[Any, float, float]] = {}

    def set(self, key: Hashable, value: Any, ttl: float) -> None:
        """Set a key in the TimedCache.

        Args:
            key: The key to set.
            value: The value of the key.
            ttl: The time to expiry of the key in the future.
        """
        self.data[key] = (value, time.time() + ttl, ttl)

    def get(self, key: Hashable) -> Any:
        """Get a timed key, deleting it if it has expired.

        Args:
            key: The key to get.

        Returns:
            The value of the key.
        """
        if key not in self.data:
            return None

        value, expiry, _ = self.data[key]

        # Remove the item if it's expired
        if expiry < time.time():
            del self.data[key]
            return None
        return value

    def renew_ttl(self, key: Hashable) -> None:
        """Renew the TTL for a key.

        Args:
            key: The key to renew the TTL.
        """
        self.set(key, self.get(key), self.data[key][2])

    def get_and_renew_ttl(self, key: Hashable) -> Any:
        """Get a key and renew it's TTL.

        Args:
            key: The key to get and renew it's TTL.

        Returns:
            The value of the key.
        """
        value = self.get(key)
        self.set(key, value, self.data[key][2])
        return value

    def __contains__(self, key: Hashable) -> bool:
        """Check if the TimedCache contains a key.

        Args:
            key: The key to check.

        Returns:
            Is the key inside the TimedCache?
        """
        return self.get(key) is not None


class BlocklistRuleItem(NamedTuple):
    """IP address and ttl for a host."""

    ip: str
    ttl: float


class Blocklist:
    """A class to store blocklist rules."""

    def __init__(
        self,
        normal_blocklist: dict[str, BlocklistRuleItem],
        fnmatch_blocklist: dict[str, BlocklistRuleItem],
    ) -> None:
        """Create an instance of Blocklist.

        Args:
            normal_blocklist: Blocklist using host to ip address syntax.
            fnmatch_blocklist: Blocklist using host to IP address syntax
            where host supports fnmatch syntax.
        """
        self.normal = normal_blocklist
        self.fnmatch = fnmatch_blocklist

    def get_name_block(self, name: str) -> str | None:
        """Find the match for a name in the blocklist.

        Args:
            name: The name to find the match.

        Returns:
            The match for the name.
        """
        if name in self.normal:
            return name
        if ret := next(
            (loc for loc in self.fnmatch.keys() if fnmatch.fnmatch(name, loc)),
            None,
        ):
            return ret
        return None

    def __getitem__(self, item: str) -> BlocklistRuleItem:
        """Get an item from the blocklist.

        Args:
            item: The item to get.

        Raises:
            KeyError: If the item isn't found.

        Returns:
            The value of the item.
        """
        if item in self.normal:
            return self.normal[item]
        if item in self.fnmatch:
            return self.fnmatch[item]
        raise KeyError(item)

    def keys(self) -> KeysView:
        """Get all the keys in the blocklist.

        Returns:
            All the keys in the blocklist.
        """
        # TODO: IDK
        return (self.normal | self.fnmatch).keys()

    def __repr__(self) -> str:
        """Repr format of Blocklist.

        Returns:
            Repr format of Blocklist.
        """
        return f"Blocklist(<{len(self.normal)} normal rules>, <{len(self.fnmatch)} fnmatch rules>)"


def encode_name_uncompressed(name: str) -> bytes:
    """Encode a DNS name without using compression.

    Args:
        name: The name to encode.

    Returns:
        The encoded DNS name.
    """
    labels = name.split(".")
    encoded = [bytes([len(label)]) + label.encode("ascii") for label in labels]
    return b"".join(encoded) + b"\x00"


def decode_name_uncompressed(buf: bytes) -> str:
    """Decode a DNS name that is uncompressed.

    Args:
        buf: The name to decode.

    Returns:
        The decoded name.
    """
    labels = []
    idx = 0
    # Extract size, parse section, until null
    while buf[idx] != 0x00:
        size = buf[idx]
        idx += 1
        label = buf[idx : idx + size]
        labels.append(label.decode("ascii"))
        idx += size
    return ".".join(labels)


class DNSDecodeLoopError(Exception):
    """An exception if a loop is encountered while encoding a DNS query."""

    pass


def decode_name(buf: bytes, start_idx: int) -> tuple[str, int]:
    """Decode a compressed DNS name from a position in a buffer.

    Args:
        buf: The buffer containing the DNS name.
        start_idx: Starting index of the DNS name.

    Raises:
        Exception: If a loop is detected.

    Returns:
        Decoded DNS name and index.
    """
    labels = []
    idx = start_idx

    # Prevent of going into a loop
    visited = set()

    while True:
        if idx in visited:
            raise DNSDecodeLoopError("Unable to decode domain: loop detected.")
        visited.add(idx)

        # Length of section
        length = buf[idx]
        # Null terminator
        if length == 0:
            idx += 1
            break
        # Pointer
        elif length & 0xC0 == 0xC0:
            # Unpack the pointer
            pointer = struct.unpack("!H", buf[idx : idx + 2])[0] & 0x3FFF
            # Recursively decode the pointer
            domain, _ = decode_name(buf, pointer)
            # Add part to domain
            labels.append(domain)

            idx += 2
            break
        else:
            # Add part to domain
            labels.append(buf[idx + 1 : idx + 1 + length].decode("ascii"))
            idx += 1 + length

    return ".".join(labels), idx


@dataclasses.dataclass(unsafe_hash=True)
class DNSHeader:
    """Dataclass to store a DNS header."""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    id_: int = 0
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 0
    ra: int = 0
    z: int = 0
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def pack(self) -> bytes:
        """Pack the DNS header into bytes.

        Returns:
            The packed DNS header.
        """
        flags = (
            (self.qr << 15)  # QR: 1 bit at bit 15
            | (self.opcode << 11)  # OPCODE: 4 bits at bits 11-14
            | (self.aa << 10)  # AA: 1 bit at bit 10
            | (self.tc << 9)  # TC: 1 bit at bit 9
            | (self.rd << 8)  # RD: 1 bit at bit 8
            | (self.ra << 7)  # RA: 1 bit at bit 7
            | (self.z << 4)  # Z: 3 bits at bits 4-6
            | (self.rcode)  # RCODE: 4 bits at bits 0-3
        )

        return struct.pack(
            "!HHHHHH",
            self.id_,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def from_buffer(cls, buf: bytes) -> "DNSHeader":
        """Create a DNSHeader instance using data stored in a buffer.

        Args:
            buf: The buffer containing a DNS header.

        Returns:
            The DNSHeader instance.
        """
        id_, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", buf[:12]
        )  # Header is always 12 bytes

        # Pack the flags
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF

        return cls(
            id_=id_,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
        )


@dataclasses.dataclass(unsafe_hash=True)
class DNSQuestion:
    """Dataclass to store a DNS question."""

    # Keep QNAME decoded, since it encoded in the message
    decoded_name: str = ""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    type_: int = 1
    class_: int = 1

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS question into bytes.

        Args:
            encoded_name: The encoded form of decoded_name.

        Returns:
            The packed DNS question.
        """

        # Require an encoded name, since compression is handled elsewhere
        return encoded_name + struct.pack("!HH", self.type_, self.class_)


@dataclasses.dataclass(unsafe_hash=True)
class DNSAnswer:
    """Dataclass to store a DNS answer."""

    # Keep NAME decoded, since it encoded in the message
    decoded_name: str = ""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
    type_: int = 1
    class_: int = 1
    ttl: int = 0
    rdlength: int = 4
    rdata: bytes = b""  # IPV4

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS answer.

        Args:
            encoded_name: The encoded form of decoded_name.

        Returns:
            The packed DNS answer.
        """
        # Require an encoded name, since compression is handled elsewhere
        return (
            encoded_name
            + struct.pack(
                "!HHIH",
                self.type_,
                self.class_,
                self.ttl,
                self.rdlength,
            )
            + self.rdata
        )


def pack_all_uncompressed(
    header: DNSHeader, questions: list[DNSQuestion] = [], answers: list[DNSAnswer] = []
) -> bytes:
    """Pack a DNS header, DNS questions, and DNS answers, without compression.

    Args:
        header: The DNS header to pack
        questions: Multiple DNS questions to pack. Defaults to [].
        answers: Multiple DNS answers to pack. Defaults to [].

    Returns:
        The packed DNS header, DNS questions, and DNS answers, without compression.
    """

    # Pack header
    response = header.pack()
    # Pack questions
    for question in questions:
        response += question.pack(encode_name_uncompressed(question.decoded_name))
    # Pack answers
    for answer in answers:
        response += answer.pack(encode_name_uncompressed(answer.decoded_name))
    return response


def pack_all_compressed(
    header: DNSHeader, questions: list[DNSQuestion] = [], answers: list[DNSAnswer] = []
) -> bytes:
    """Pack a DNS header, DNS questions, and DNS answers, with compression.

    Args:
        header: The DNSHeader to pack.
        questions: Multiple DNS questions to pack. Defaults to [].
        answers: Multiple DNS answers to pack. Defaults to [].

    Returns:
        The packed DNS header, DNS questions, and DNS answers, with compression.
    """
    # Pack header
    response = header.pack()
    # Store pointer locations
    name_offset_map: dict[str, int] = {}

    # Compress question + answers
    # Pack + store names + compression
    for question in questions:
        # If the name is repeated
        if question.decoded_name in name_offset_map:
            # Starting pointer + offset of name
            pointer = 0xC000 | name_offset_map[question.decoded_name]

            encoded_name = struct.pack("!H", pointer)
        else:
            # Otherwise, encode the name without compression
            encoded_name = encode_name_uncompressed(question.decoded_name)
            # Store the name for future pointers
            name_offset_map[question.decoded_name] = len(response)

        response += question.pack(encoded_name)

    for answer in answers:
        if answer.decoded_name in name_offset_map:
            # Starting pointer + offset of name
            pointer = 0xC000 | name_offset_map[answer.decoded_name]

            encoded_name = struct.pack("!H", pointer)
        else:
            encoded_name = encode_name_uncompressed(answer.decoded_name)
            name_offset_map[answer.decoded_name] = len(response)

        response += answer.pack(encoded_name)

    return response


def unpack_all(
    buf: bytes,
) -> tuple[DNSHeader, list[DNSQuestion], list[DNSAnswer]]:
    """Unpack a buffer into a DNS header, DNS questions, and DNS answers.

    Args:
        buf: Buffer containing a DNS header, DNS questions, DNS answers.

    Returns:
        The DNS header, DNS answers, and DNS questions.
    """

    # Header isn't compressed
    # Load the first 12 bytes into the header
    header = DNSHeader.from_buffer(buf[:12])

    # Start after the header
    idx = 12

    questions = []

    # Use header.qdcount for # of questions
    for _ in range(header.qdcount):
        # Decode the name
        decoded_name, idx = decode_name(buf, idx)

        # Unpack the other fields
        type_, class_ = struct.unpack("!HH", buf[idx : idx + 4])
        idx += 4

        questions.append(
            DNSQuestion(decoded_name=decoded_name, type_=type_, class_=class_)
        )

    answers = []
    # use header.ancount for # of answers
    for _ in range(header.ancount):
        # Decode the name
        decoded_name, idx = decode_name(buf, idx)

        # Decode required fields
        type_, class_ = struct.unpack("!HH", buf[idx : idx + 4])
        idx += 4

        # Struct format
        # https://docs.python.org/3/library/struct.html
        # Big indian unsigned int, 4 bytess
        ttl = struct.unpack("!I", buf[idx : idx + 4])[0]
        idx += 4

        # Big endian unsigned short, 2 bytes
        rdlength = struct.unpack("!H", buf[idx : idx + 2])[0]
        idx += 2

        # Use rdlength to get rdata
        rdata = buf[idx : idx + rdlength]
        idx += rdlength

        answers.append(
            DNSAnswer(
                decoded_name=decoded_name,
                type_=type_,
                class_=class_,
                ttl=ttl,
                rdlength=rdlength,
                rdata=rdata,
            )
        )

    # Return empty questions and answers, rather than None, due to mypy
    return header, questions, answers


class ServerManager:
    """A class to store a server session."""

    def __init__(
        self,
        host: tuple[str, int],
        resolver: tuple[str, int],
        blocklist: Blocklist,
    ) -> None:
        """Create a ServerManager instance.

        Args:
            host: Host and port of server.
            resolver: Host and port of resolver.
            blocklist: Blocklist of sites.
        """
        self.host = host

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(host)

        self.resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.resolver_socket_addr = resolver

        self.blocklist = blocklist

        self.cache = TimedCache()

        # TODO: This probably doesn't have much of an advantage
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
                # TODO: Fix
                self.blocklist.normal[_host].ttl,
            )

    def intercept_questions(self):
        # Cached, blocked
        pass

    def handle_dns_query(self, buf: bytes) -> bytes:
        """Handle an incoming DNS query. Block IP addresses on the blocklist,
        and forward those not to the resolver.

        Args:
            buf: The buffer containing a DNS query.

        Returns:
            The response.
        """

        logging.info("Received query")

        # Recieve header and questions
        header, questions, _ = unpack_all(buf)

        logging.debug("Received query: %s, %s", header, questions)

        # check cache for all

        # Copy header
        new_header = dataclasses.replace(header)
        new_questions = []
        question_index_blocked = []
        question_index_cached = []

        # Remove blocked sites, so it doesn't get forwarded
        # Remove cached sites, so it doesn't get forwarded
        for idx, question in enumerate(questions):
            if question in self.cache:
                question_index_cached.append(idx)
            # Use file matching syntax to detect block
            elif question_index_match := self.blocklist.get_name_block(
                question.decoded_name
            ):
                question_index_blocked.append((idx, question_index_match))
            else:
                new_questions.append(question)

        # Set new qdcount for forwarded header
        new_header.qdcount = len(new_questions)

        logging.debug("New header %s, new questions %s", new_header, new_questions)

        # Only forward query if there is something to forward
        if new_header.qdcount > 0:
            # Process header, questions
            # Repack data
            send = pack_all_compressed(new_header, new_questions)
            response = self.forward_dns_query(send)

            logging.debug("Received query from DNS server")

            # Add the blocked sites to the response
            recv_header, recv_questions, recv_answers = unpack_all(response)

            if len(recv_answers) == 0:
                recv_answers = []
        else:
            recv_header = new_header
            # QR = 0 for queries, QR = 1 for responses
            recv_header.qr = 1
            recv_questions = new_questions
            recv_answers = []

        # Disable the recursion flag for cached or blocked queries
        # I'm not sure how much this actually works
        # https://serverfault.com/a/729121
        if len(question_index_cached) > 0 or len(question_index_blocked) > 0:
            recv_header.rd = 0
            recv_header.ra = 0

        # Add the cached questions to the response, keeping the position
        for idx in question_index_cached:
            question = questions[idx]
            recv_questions.insert(idx, question)
            recv_answers.insert(idx, self.cache.get_and_renew_ttl(question))

        # Add the blocked questions to the response, keeping the position
        for idx, match in question_index_blocked:
            question = questions[idx]
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
            recv_questions.insert(idx, question)
            recv_answers.insert(idx, answer)

        # Update the header's question and answer count
        recv_header.qdcount = len(recv_questions)
        recv_header.ancount = len(recv_answers)

        logging.debug(
            "Sending query back, %s, %s, %s", recv_header, recv_questions, recv_answers
        )

        # Since we have a new response, cache it, using the original question and new answer
        for cache_question, cache_answer in zip(questions, recv_answers):
            # if cache_questio
            # self.cache[cache_question]
            if cache_question not in self.cache:
                self.cache.set(cache_question, cache_answer, cache_answer.ttl)

        # Pack and compress header, questions, answers
        return pack_all_compressed(recv_header, recv_questions, recv_answers)

    def forward_dns_query(self, query: bytes) -> bytes:
        """Forward a DNS query to an address.

        Args:
            query: The DNS query to forward.

        Returns:
            The response from the forwarding server.
        """
        self.resolver_socket.sendto(query, self.resolver_socket_addr)

        response, _ = self.resolver_socket.recvfrom(512)
        return response

    def done(self) -> None:
        """Handle destroying the sockets."""
        # TODO: What about using a context manager? Pointless idea, but anyway
        self.sock.close()
        self.resolver_socket.close()

    def threaded_handle_dns_query(
        self, addr: tuple[str, int], lock: threading.Lock, *args, **kwargs
    ) -> None:
        """Run a threaded version of handle_dns_query.

        Args:
            addr: Address of client.
            lock: Thread lock.
            *args: Arguments to pass to `self.handle_dns_query`.
            **kwargs: Keyword arguments to pass to `self.handle_dns_query`.
        """
        # t = time.time()
        response = self.handle_dns_query(*args, **kwargs)
        # logging.warning(time.time() - t)

        with lock:
            self.sock.sendto(response, addr)

        # self.sock.sendto(self.handle_dns_query(*args, **kwargs), addr)
        logging.info("Sent response")

    def start_threaded(self) -> None:
        """Start a threaded server."""

        logging.info("Threaded DNS Server running at %s:%s", self.host[0], self.host[1])

        # Lock sockets send back
        lock = threading.Lock()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            while True:
                try:
                    # Recieve packet
                    buf, addr = self.sock.recvfrom(512)

                    executor.submit(self.threaded_handle_dns_query, addr, lock, buf)
                except Exception:
                    # Handle errors, but keep the program running
                    self.done()
                    logging.error("Error", exc_info=True)

    def start(self) -> None:
        """Start a non-threaded server."""
        logging.info("DNS Server running at %s:%s", self.host[0], self.host[1])
        while True:
            try:
                buf, addr = self.sock.recvfrom(512)
                response = self.handle_dns_query(buf)
                self.sock.sendto(response, addr)
                logging.info("Sent response")
            except Exception:
                self.done()
                logging.error("Error", exc_info=True)


@functools.cache
def is_ip_addr_valid(ip_addr: str) -> bool:
    """Check if an IP address is valid. This function caches the validity of an
    IP address.

    Args:
        ip_addr: The IP address to check validity.

    Returns:
        Is the IP address valid?
    """
    try:
        socket.inet_aton(ip_addr)
        return True
    except socket.error:
        return False


def is_fnmatch_host(host: str) -> bool:
    """Check if a host uses fnmatch syntax.

    Args:
        host: The host to check.

    Returns:
        Does the host use fnmatch syntax?
    """ """"""
    return any(x in host for x in FNMATCH_CHARS)


# I don't know how to get mypt to accept data: dict | list[bytes] so I set it to any instead
def parse_blocklist(
    data: Any, master_ttl: int
) -> tuple[dict[str, BlocklistRuleItem], dict[str, BlocklistRuleItem]]:
    """Parse a blocklist.

    Args:
        data: The blocklist to parse.
        master_ttl: Master TTL if TTL isn't set.

    Returns:
        One dictionary of hosts to IP addresses, another dictionary of hosts
        using fnmatch syntax to IP addresses.
    """

    # TODO: Validate ip
    # TODO: Check for collision
    normal_blocklist = {}
    fnmatch_blocklist = {}

    # Hosts format
    if isinstance(data, list):
        for line in data:
            line = line.decode()
            if not line.startswith("#"):
                ip, host = line.strip().split()
                item = BlocklistRuleItem(ip=ip, ttl=master_ttl)
                if is_fnmatch_host(host):
                    fnmatch_blocklist[host] = item
                else:
                    normal_blocklist[host] = item
    else:
        # Normal format
        ttl = data.get("ttl", master_ttl)
        for host, block_ip in data.get("blocklist", {}).items():
            item = BlocklistRuleItem(ip=block_ip, ttl=ttl)
            if is_fnmatch_host(host):
                fnmatch_blocklist[host] = item
            else:
                normal_blocklist[host] = item

        for rule in data.get("rules", []):
            block_ip = rule["block_ip"]
            rule_ttl = rule.get("ttl", ttl)
            for host in rule["hosts"]:
                item = BlocklistRuleItem(ip=block_ip, ttl=rule_ttl)
                if is_fnmatch_host(host):
                    fnmatch_blocklist[host] = item
                else:
                    normal_blocklist[host] = item

    # TODO: Explicit return tuple?
    return normal_blocklist, fnmatch_blocklist


def read_blocklist(
    fpath: str, master_ttl: int
) -> tuple[dict[str, BlocklistRuleItem], dict[str, BlocklistRuleItem]]:
    """Read and parse blocklist from a file.

    Args:
        fpath: The path to the file.
        master_ttl: Master TTL if TTL isn't set.

    Raises:
        Exception: Unknown file extension.

    Returns:
        A parsed blocklist.
    """
    with open(fpath, "rb") as f:
        ext = os.path.splitext(fpath)[1]
        if ext == ".json":
            return parse_blocklist(json.load(f), master_ttl)
        elif ext == ".toml":
            return parse_blocklist(tomllib.load(f), master_ttl)
        else:
            return parse_blocklist(f.readlines(), master_ttl)


def load_all_blocklists(paths: list[str], master_ttl: int) -> Blocklist:
    """Load all blocklists from a list of paths.

    Args:
        paths: A list containing paths to the blocklist.
        master_ttl: Master TTL if TTL isn't set.


    Returns:
        The blocklist from those files.
    """
    normal_blocklist = {}
    fnmatch_blocklist = {}
    for path in paths:
        normal_b, fnmatch_b = read_blocklist(path, master_ttl)
        normal_blocklist.update(normal_b)
        fnmatch_blocklist.update(fnmatch_b)
    return Blocklist(normal_blocklist, fnmatch_blocklist)


def cli() -> None:
    """The command line interface for compactdns."""
    # TODO: Document this more
    parser = argparse.ArgumentParser(
        description="A simple forwarding DNS server", fromfile_prefix_chars="@"
    )
    parser.add_argument(
        "--host",
        "-a",
        required=True,
        type=str,
        help="The host address in the format of a.b.c.d:port",
    )
    parser.add_argument(
        "--resolver",
        "-r",
        required=True,
        type=str,
        help="The resolver address in the format of a.b.c.d:port",
    )
    parser.add_argument(
        "--blocklist",
        "-b",
        # required=False
        type=str,
        help="Path to file containing blocklist",
        nargs="*",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        choices=list(logging.getLevelNamesMapping().keys()),
        default="INFO",
        type=str,
        help="Provide information about the logging level (default = info)",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["normal", "threaded"],
        default="threaded",
        type=str,
        help="Mode to run server (default = threaded)",
    )
    parser.add_argument(
        "--ttl",
        default=300,
        type=int,
        help="Default TTL for blocked hosts (default = 300)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=args.loglevel.upper(),
        format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    host = args.host.split(":")
    resolver = args.resolver.split(":")

    if args.blocklist is not None:
        blocklist = load_all_blocklists(args.blocklist, args.ttl)
    else:
        blocklist = Blocklist({}, {})

    logging.debug("Blocklist: %s", blocklist)

    manager = ServerManager(
        host=(host[0], int(host[1])),
        resolver=(resolver[0], int(resolver[1])),
        blocklist=blocklist,
    )

    if args.mode == "normal":
        manager.start()
    elif args.mode == "threaded":
        manager.start_threaded()


if __name__ == "__main__":
    cli()
