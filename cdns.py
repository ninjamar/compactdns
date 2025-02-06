#!/usr/bin/env python3

# dns-server
# A simple forwarding DNS server with blocking capabilities
# https://github.com/ninjamar/compactdns
# Copyright (c) 2025 ninjamar
# LICENSE 

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

# TODO: Turn this into a module in a directory
# TODO: Document the archictecture (comments)
# TODO: Ensure all code is right (via tests)

# TODO: Benchmark
# TODO: Make sure the threading part of the server is working

# TODO: Make sure cache is better
# TODO: use TimedCache to store blocklist in a better way

# TODO: Type annotations
# TODO: Consistent naming for builtin methods on classes

# TODO: Configuration file format other than fromfile_prefix_chars
# TODO: Support /etc/hosts syntax

DEFAULT_TTL = 300

class TimedCache:
    """Basically a dictionary but except the keys expire after some time"""

    def __init__(self):
        """Create a TimedCache instance"""
        self.data = {}

    def set(self, key, value, ttl):
        """Set a key

        :param key: the key to set
        :type key: Hashable
        :param value: the value to set
        :type value: Any
        :param ttl: duration of key
        :type ttl: int
        """
        self.data[key] = (value, time.time() + ttl)

    def get(self, key):
        """Get a timed, key, deleting it if it expires

        :param key: the key to get
        :type key: Hashable
        :return: value for key
        :rtype: _Any
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
        """Check if cache contains key

        :param key: key to check
        :type key: Hashable
        :return: is the key inside the cache?
        :rtype: bool
        """
        return self.get(key) != None


def encode_name_uncompressed(name: str) -> bytes:
    """Encode a DNS name, without compression

    :param name: DNS name to encode
    :type name: str
    :return: encoded DNS name
    :rtype: bytes
    """
    labels = name.split(".")
    encoded = [bytes([len(label)]) + label.encode("ascii") for label in labels]
    return b"".join(encoded) + b"\x00"


def decode_name_uncompressed(buf: bytes) -> str:
    """Decode a DNS name, without compression

    :param buf: DNS name to decode
    :type buf: bytes
    :return: decoded DNS name
    :rtype: str
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


def decode_name(buf: bytes, start_idx: int) -> str:
    """Decode a name, that is compressed, from a buffer

    :param buf: buffer containing name
    :type buf: bytes
    :param start_idx: start index of name
    :type start_idx: int
    :raises Exception: infinite loop
    :return: decoded name
    :rtype: str
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
    """Dataclass to store DNS header"""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    id: int = 0
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
        """Pack the DNS header

        :return: packed DNS header
        :rtype: bytes
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
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def from_buffer(cls, buf: bytes) -> "DNSHeader":
        """Create a DNSHeader object from a buffer

        :param buf: buffer containing a DNS header
        :type buf: bytes
        :return: DNS header
        :rtype: DNSHeader
        """
        id_, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", buf[:12]
        )  # Header is always 12 bytes
        flags = flags
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        return cls(
            id=id_,
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
    """Dataclass to store DNS question"""

    # Keep QNAME decoded, since it encoded in the message
    decoded_name: str = ""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    type_: int = 1
    class_: int = 1

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS question

        :param encoded_name: encoded name
        :type encoded_name: bytes
        :return: packed DNS question
        :rtype: bytes
        """

        # Require an encoded name, since compression is handled elsewhere
        return encoded_name + struct.pack("!HH", self.type_, self.class_)


@dataclasses.dataclass(unsafe_hash=True)
class DNSAnswer:
    """Dataclass to store DNS answer"""

    # Keep NAME decoded, since it encoded in the message
    decoded_name: str = ""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
    type_: int = 1
    class_: int = 1
    ttl: int = 0
    rdlength: int = 4
    rdata: str = ""  # IPV4

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS answer

        :param encoded_name: name encoded
        :type encoded_name: bytes
        :return: packed DNS answer
        :rtype: bytes
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
    header: DNSHeader, questions: list[DNSQuestion], answers: list[DNSAnswer]
) -> bytes:
    """Pack DNS headers, questions, and answers, without compression

    :param header: A singular DNS header
    :type header: DNSHeader
    :param questions: All the DNS questions
    :type questions: list[DNSQuestion]
    :param answers: All the DNS answers
    :type answers: list[DNSAnswer]
    :return: uncompressed DNS bytes
    :rtype: bytes
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
    """Pack DNS headers, questions, and answers, with compression

    :param header: A singular DNS header
    :type header: DNSHeader
    :param questions: All the DNS questions
    :type questions: list[DNSQuestion]
    :param answers: All the DNS answers
    :type answers: list[DNSAnswer]
    :return: compressed DNS bytes
    :rtype: bytes
    """
    # Pack header
    response = header.pack()
    # Store pointer locations
    name_offset_map = {}

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
) -> (
    tuple[DNSHeader, list[DNSQuestion]]
    | tuple[DNSHeader, list[DNSQuestion], list[DNSAnswer]]
):
    """Unpack a sent buffer into the header and questions

    :param buf: sent buffer
    :type buf: bytes
    :return: unpacked header and questions
    :rtype: tuple[DNSHeader, DNSQuestion]
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

    # If there aren't any answers, don't return it
    return (header, questions) if header.ancount == 0 else (header, questions, answers)


class ServerManager:
    """A server session"""

    def __init__(
        self,
        # resolver_socket: socket.socket,
        host,
        resolver_addr: tuple[str, int],
        blocklist: dict[str, tuple[str, int]],
    ):
        """Create a ServerManager instance

        :param resolver_socket: socket to use to send by resolver_socket_addr
        :type resolver_socket: socket.socket
        :param resolver_socket_addr: socket addr and port
        :type resolver_socket_addr: tuple[str, int]
        :param blocklist: host : (ip, ttl)
        :type blocklist: dict[str, tuple[str, int]]
        """
        self.host = host

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(host)

        self.resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.resolver_socket_addr = resolver_addr

        self.blocklist = blocklist

        self.cache = TimedCache()

        # Cache individual hosts that don't contain any special syntax
        # TODO: This just assumes type and class but it needs to be better
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
        """Handle a DNS query

        :param buf: buffer containing DNS query
        :type buf: bytes
        :return: response from server
        :rtype: bytes
        """
        logging.info("Received query")

        # Recieve header and questions
        header, questions = unpack_all(buf)

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
            recv = unpack_all(response)
            recv_header = recv[0]
            recv_questions = recv[1]
            # Sometimes there will be no answers
            recv_answers = recv[2] if len(recv) > 2 else []
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
        """Forward a DNS query to an address

        :param query: query to forward
        :type query: bytes
        :param addr: tuple containing address and port
        :type addr: tuple[str, int]
        :return: response from the server
        :rtype: bytes
        """

        self.resolver_socket.sendto(query, self.resolver_socket_addr)

        response, _ = self.resolver_socket.recvfrom(512)
        return response

    def done(self):
        """Close sockets"""
        self.sock.close()
        self.resolver_socket.close()

    def threaded_handle_dns_query(self, addr, lock, *args, **kwargs):
        """Run a threaded version of handle_dns_query

        :param addr: address + port of client
        :type addr: tuple[str, int]
        """
        response = self.handle_dns_query(*args, **kwargs)
        with lock:
            self.sock.sendto(response, addr)
        # self.sock.sendto(self.handle_dns_query(*args, **kwargs), addr)
        logging.info("Sent response")

    def start_threaded(self):
        """Start a threaded server"""
        logging.info(f"Threaded DNS Server running at {self.host[0]}:{self.host[1]}")

        # Lock sockets send back
        lock = threading.Lock()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            while True:
                try:
                    # Recieve packet
                    buf, addr = self.sock.recvfrom(512)

                    executor.submit(self.threaded_handle_dns_query, addr, lock, buf)
                except Exception as e:
                    # Handle errors, but keep the program running
                    self.done()
                    logging.error("Error", exc_info=1)

    def start(self):
        """Start a non-threaded server"""
        logging.info(f"DNS Server running at {self.host[0]}:{self.host[1]}")
        while True:
            try:
                buf, addr = self.sock.recvfrom(512)
                response = self.handle_dns_query(buf)
                self.sock.sendto(response, addr)
                logging.info("Sent response")
            except Exception as e:
                self.done()
                logging.error("Error", exc_info=1)


@functools.cache
def is_ip_addr_valid(ip_addr: str) -> bool:
    """Check if an IP address is valid
    This function is cached

    :param ip_addr: ip ap address
    :type ip_addr: str
    :return: is the ip address valid
    :rtype: bool
    """
    try:
        socket.inet_aton(ip_addr)
        return True
    except socket.error:
        return False


def parse_blocklist(data: dict) -> dict[str, tuple[str, int]]:
    """Parse a blocklist

    :param data: blocklist to parse
    :type data: dict
    :return: parsed version of blocklist
    :rtype: dict[str, tuple[str, int]]
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
    """Read a blocklist from a file

    :param fpath: path to file
    :type fpath: str
    :raises Exception: unknown file extension
    :return: blocklist
    :rtype: dict[str, tuple[str, int]]
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
    """Load all blocklists from paths

    :param paths: files containing blocklists
    :type paths: list[str]
    :return: parsed blocklists
    :rtype: dict[str, tuple[str, int]]
    """
    blocklist = {}
    for path in paths:
        blocklist.update(read_blocklist(path))
    return blocklist


def cli():
    """Command line interface"""
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
        blocklist = dict()

    logging.debug(f"Blocklist: {blocklist}")

    manager = ServerManager(
        host=(host[0], int(host[1])),
        resolver_addr=(resolver[0], int(resolver[1])),
        blocklist=blocklist,
    )

    if args.mode == "normal":
        manager.start()
    elif args.mode == "threaded":
        manager.start_threaded()


if __name__ == "__main__":
    cli()
