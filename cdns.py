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

# TODO: Verbose mode (better logging stuff)

# TODO: Turn this into a module in a directory
# TODO: When this is a module, maybe allow some DNS tunneling and messaging stuff?
# TODO: Document the archictecture (comments)
# TODO: Ensure all code is right (via tests)

# TODO: Benchmark
# TODO: Make sure the threading part of the server is working

# TODO: Make sure cache is better
# TODO: use TimedCache to store blocklist in a better way

# TODO: Convert documentation to google-notypes
# TODO: Should docstrings be formatted as using a period
# TODO: Type annotations
# TODO: Consistent naming for builtin methods on classes

# TODO: Configuration file format other than fromfile_prefix_chars
# TODO: Support /etc/hosts syntax

DEFAULT_TTL = 300


class TimedCache:
    """A dictionary, with expiring keys."""

    def __init__(self):
        """Create a TimedCache instance."""
        self.data = {}

    def set(self, key, value, ttl):
        """
        Set a key in the TimedCache.

        Args:
            key: The key to set
            value: The value of the key
            ttl: The time to expiry of the key in the future
        """
        self.data[key] = (value, time.time() + ttl)

    def get(self, key):
        """
        Get a timed key, deleting it if it has expired.

        Args:
            key: The key to get

        Returns:
            The value of the key
        """
        if key not in self.data:
            return None

        value, expiry = self.data[key]

        # Remove the item if it's expired
        if expiry < time.time():
            del self.data[key]
            return None
        return value

    def __contains__(self, key) -> bool:
        """
        Check if the TimedCache contains a key.

        Args:
            key: The key to check

        Returns:
            Is the key inside the TimedCache?
        """
        return self.get(key) is not None


def encode_name_uncompressed(name: str) -> bytes:
    """
    Encode a DNS name without using compression.

    Args:
        name: The name to encode

    Returns:
        The encoded DNS name
    """
    labels = name.split(".")
    encoded = [bytes([len(label)]) + label.encode("ascii") for label in labels]
    return b"".join(encoded) + b"\x00"


def decode_name_uncompressed(buf: bytes) -> str:
    """
    Decode a DNS name that is uncompressed.

    Args:
        buf: The name to decode

    Returns:
        The decoded name
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


def decode_name(buf: bytes, start_idx: int) -> tuple[str, int]:
    """
    Decode a compressed DNS name from a position in a buffer.

    Args:
        buf: The buffer containing the DNS name
        start_idx: Starting index of the DNS name

    Raises:
        Exception: A loop is detected

    Returns:
        Decoded DNS name and index
    """
    labels = []
    idx = start_idx

    # Prevent of going into a loop
    visited = set()

    while True:
        if idx in visited:
            raise Exception("Unable to decode domain: loop detected")
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
        """
        Pack the DNS header into bytes.

        Returns:
            The packed DNS header
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
        """
        Create a DNSHeader instance using data stored in a buffer

        Args:
            buf: The buffer containing a DNS header

        Returns:
            The DNSHeader instance
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
        """
        Pack the DNS question into bytes.

        Args:
            encoded_name: The encoded form of decoded_name

        Returns:
            The packed DNS question
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
        """
        Pack the DNS answer.

        Args:
            encoded_name: The encoded form of decoded_name

        Returns:
            The packed DNS answer
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
    """
    Pack a DNS header, DNS questions, and DNS answers, without compression.

    Args:
        header: The DNS header to pack
        questions: Multiple DNS questions to pack. Defaults to [].
        answers: Multiple DNS answers to pack. Defaults to [].

    Returns:
        The packed DNS header, DNS questions, and DNS answers, without compression
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
    """
    Pack a DNS header, DNS questions, and DNS answers, with compression.

    Args:
        header: The DNSHeader to pack
        questions: Multiple DNS questions to pack. Defaults to [].
        answers: Multiple DNS answers to pack. Defaults to [].

    Returns:
        The packed DNS header, DNS questions, and DNS answers, with compression
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
) -> tuple[DNSHeader, list[DNSQuestion] | None, list[DNSAnswer] | None]:
    """
    Unpack a buffer into a DNS header, DNS questions, and DNS answers.

    Args:
        buf: Buffer containing a DNS header, DNS questions, DNS answers

    Returns:
        The DNS header, DNS answers, and DNS questions
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

    # If there aren't any questions, answers, return None instead
    return (
        header,
        None if len(questions) == 0 else questions,
        None if len(answers) == 0 else answers,
    )


class ServerManager:
    """A class to store a server session."""

    def __init__(
        self,
        host: tuple[str, int],
        resolver: tuple[str, int],
        blocklist: dict[str, tuple[str, int]],
    ):
        """
        Create a ServerManager instance.

        Args:
            host: Host and port of server
            resolver: Host and port of resolver
            blocklist: Blocklist of sites
        """
        self.host = host

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(host)

        self.resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.resolver_socket_addr = resolver

        self.blocklist = blocklist

        self.cache = TimedCache()

        # Cache individual hosts that don't contain any special syntax
        # Caching is for when type_ and class_ is 1
        for host in self.blocklist.keys():
            if not any(x in host for x in "*?[]!"):
                self.cache.set(
                    DNSQuestion(decoded_name=host, type_=1, class_=1),
                    DNSAnswer(
                        decoded_name=host,
                        type_=1,
                        class_=1,
                        ttl=self.blocklist[host][1],
                        rdlength=4,
                        # inet_aton encodes a ip address into bytes
                        rdata=socket.inet_aton(self.blocklist[host][0]),
                    ),
                    # TODO: Fix
                    self.blocklist[host][1],
                )

    def handle_dns_query(self, buf: bytes) -> bytes:
        """
        Handle an incoming DNS query. Block IP addresses on the blocklist, and forward those not to the resolver.

        Args:
            buf: The buffer containing a DNS query

        Returns:
            The response
        """
        # TODO: Document this function more

        logging.info("Received query")

        # Recieve header and questions
        header, questions, _ = unpack_all(buf)

        logging.debug(f"Received query: {header}, {questions}")

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
            elif question_index_match := next(
                (
                    loc
                    for loc in self.blocklist.keys()
                    if fnmatch.fnmatch(question.decoded_name, loc)
                ),
                None,
            ):
                question_index_blocked.append((idx, question_index_match))
            else:
                new_questions.append(question)

        # Set new qdcount for forwarded header
        new_header.qdcount = len(new_questions)

        logging.debug(f"New header {new_header}, new questions {new_questions}")

        # Only forward query if there is something to forward
        if new_header.qdcount > 0:
            # Process header, questions
            # Repack data
            send = pack_all_compressed(new_header, new_questions)
            response = self.forward_dns_query(send)

            logging.debug("Received query from dns server")

            # Add the blocked sites to the response
            recv_header, recv_questions, recv_answers = unpack_all(response)

            if recv_answers is None:
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
            recv_answers.insert(idx, self.cache.get(question))
            # Update question answer for header

        # Add the blocked questions to the response, keeping the position
        for idx, match in question_index_blocked:
            question = questions[idx]
            # Fake answer
            answer = DNSAnswer(
                decoded_name=question.decoded_name,
                type_=question.type_,
                class_=question.type_,
                ttl=self.blocklist[match][1],
                rdlength=4,
                # inet_aton encodes a ip address into bytes
                rdata=socket.inet_aton(self.blocklist[match][0]),
            )

            # Insert the questions and answer to the correct spot
            recv_questions.insert(idx, question)
            recv_answers.insert(idx, answer)

        # Update the header's question and answer count
        recv_header.qdcount = len(recv_questions)
        recv_header.ancount = len(recv_answers)

        logging.debug(
            f"Sending query back, {recv_header}, {recv_questions}, {recv_answers}"
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
        """
        Forward a DNS query to an address.

        Args:
            query: The DNS query to forward

        Returns:
            The response from the forwarding server
        """
        self.resolver_socket.sendto(query, self.resolver_socket_addr)

        response, _ = self.resolver_socket.recvfrom(512)
        return response

    def done(self):
        """
        Handle destroying the sockets.
        """
        # TODO: What about using a context manager? Pointless idea, but anyway
        self.sock.close()
        self.resolver_socket.close()

    def threaded_handle_dns_query(
        self, addr: socket._RetAddress, lock: threading.Lock, *args, **kwargs
    ):
        """
        Run a threaded version of handle_dns_query.

        Args:
            addr: Address to client
            lock: Thread lock
        """
        # t = time.time()
        response = self.handle_dns_query(*args, **kwargs)
        # logging.warning(time.time() - t)

        with lock:
            self.sock.sendto(response, addr)

        # self.sock.sendto(self.handle_dns_query(*args, **kwargs), addr)
        logging.info("Sent response")

    def start_threaded(self):
        """
        Start a threaded server.
        """

        logging.info(f"Threaded DNS Server running at {self.host[0]}:{self.host[1]}")

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
                    logging.error("Error", exc_info=1)

    def start(self):
        """
        Start a non-threaded server.
        """
        logging.info(f"DNS Server running at {self.host[0]}:{self.host[1]}")
        while True:
            try:
                buf, addr = self.sock.recvfrom(512)
                response = self.handle_dns_query(buf)
                self.sock.sendto(response, addr)
                logging.info("Sent response")
            except Exception:
                self.done()
                logging.error("Error", exc_info=1)


@functools.cache
def is_ip_addr_valid(ip_addr: str) -> bool:
    """
    Check if an IP address is valid. This function caches the validity of an IP address.

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


def parse_blocklist(data: dict) -> dict[str, tuple[str, int]]:
    """
    Parse a blocklist.

    Args:
        data: The blocklist to parse

    Returns:
        A dictionary of hosts to ip addresses.
    """

    # TODO: Validate ip
    # TODO: Check for collision
    blocklist = {}

    ttl = data.get("ttl", DEFAULT_TTL)
    for host, block_ip in data.get("blocklist", {}).items():
        blocklist[host] = (block_ip, ttl)

    for rule in data.get("rules", []):
        block_ip = rule["block_ip"]
        rule_ttl = rule.get("ttl", ttl)
        for host in rule["hosts"]:
            blocklist[host] = (block_ip, rule_ttl)
    return blocklist


def read_blocklist(fpath: str) -> dict[str, tuple[str, int]]:
    """
    Read and parse blocklist from a file.

    Args:
        fpath: The path to the file

    Raises:
        Exception: Unknown file extension

    Returns:
        A parsed blocklist
    """
    with open(fpath, "rb") as f:
        ext = os.path.splitext(fpath)[1]
        if ext == ".json":
            return parse_blocklist(json.load(f))
        elif ext == ".toml":
            return parse_blocklist(tomllib.load(f))
        else:
            raise Exception("Unable to read blocklist: unknown file extension")


def load_all_blocklists(paths: list[str]) -> dict[str, tuple[str, int]]:
    """
    Load all blocklists from a list of paths.

    Args:
        paths: A list containing paths to the blocklist

    Returns:
        The blocklist from those files
    """
    blocklist = {}
    for path in paths:
        blocklist.update(read_blocklist(path))
    return blocklist


def cli():
    """
    The command line interface for compactdns.s
    """
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
        "--ttl", default=60, type=int, help="Default TTL for blocked hosts"
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
        blocklist = load_all_blocklists(args.blocklist)
    else:
        blocklist = {}

    logging.debug(f"Blocklist: {blocklist}")

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
