#!/usr/bin/env python3

# dns-server
# A simple forwarding DNS server
# https://github.com/ninjamar/dns-server
# Version 0.0.1

import argparse
import logging
import socket
import struct
import dataclasses
import fnmatch
import threading

# Default configuration/settings

DEFAULT_BLOCKING_TTL = 60
# Use fnmatch synatax to match domains
BLOCKLIST = ["google.*", "*.google.*"]
# Redirect to IP after block
BLOCK_IP = "127.0.0.1"
# TODO: Use class, and cache?
# TODO: Host something on block ip
# TODO: Ensure all code is right (via tests)
# TODO: Document the archictecture (comments)
# TODO: Reuse forwarding socket3
# TODO: Time request
# TODO: More threads
# TODO: Add timeout
# TODO: Load configuration from file


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


@dataclasses.dataclass
class DNSHeader:
    """Dataclass to store DNS header"""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    id: int = 0  # TODO: BUILTIN
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
        unpacked = struct.unpack("!HHHHHH", buf[:12])  # Header is always 12 bytes
        flags = unpacked[1]
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        return cls(
            id=unpacked[0],
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=unpacked[2],
            ancount=unpacked[3],
            nscount=unpacked[4],
            arcount=unpacked[5],
        )


@dataclasses.dataclass
class DNSQuestion:
    """Dataclass to store DNS question"""

    # Keep QNAME decoded, since it encoded in the message
    decoded_name: str = ""

    # Required fields
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    type_: int = 1  # TODO: BUILTIN
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


@dataclasses.dataclass
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
    # TODO: Type annotations
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
    def __init__(
        self,
        # resolver_socket: socket.socket,
        host,
        resolver_addr: tuple[str, int],
        blocklist: set[str],
        redirect_ip: str,
    ):
        """Create a ServerManager instance

        :param resolver_socket: socket to use to send by resolver_socket_addr
        :type resolver_socket: socket.socket
        :param resolver_socket_addr: socket addr and port
        :type resolver_socket_addr: tuple[str, int]
        :param blocklist: block these websites
        :type blocklist: set[str]
        :param redirect_ip: answer with ip on block
        :type redirect_ip: str
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(host)

        self.resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.resolver_socket_addr = resolver_addr

        self.blocklist = blocklist
        self.redirect_ip = redirect_ip

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

        # Copy header
        new_header = dataclasses.replace(header)
        new_questions = []
        questions_index_blocked = []

        # Remove blocked sites, so it doesn't get forwarded
        for idx, question in enumerate(questions):
            # Use file matching syntax to detect block
            if any(
                fnmatch.fnmatch(question.decoded_name, loc) for loc in self.blocklist
            ):
                questions_index_blocked.append(idx)
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
            recv_questions = new_questions
            recv_answers = []

        # Add the blocked questions to the response, keeping the position
        for idx in questions_index_blocked:
            question = questions[idx]
            # Fake answer
            answer = DNSAnswer(
                decoded_name=question.decoded_name,
                type_=question.type_,
                class_=question.type_,
                ttl=DEFAULT_BLOCKING_TTL,
                rdlength=4,
                # inet_aton encodes a ip address into bytes
                rdata=socket.inet_aton(self.redirect_ip),
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

        # TODO: Use a class, and keep the same socket open
        self.resolver_socket.sendto(query, self.resolver_socket_addr)

        response, _ = self.resolver_socket.recvfrom(512)
        # resolver_socket.close()  # should i use the same socket?
        return response

    def done(self):
        self.sock.close()
        self.resolver_socket.close()

    def threaded_handle_dns_query(self, addr, *args, **kwargs):
        self.sock.sendto(self.handle_dns_query(*args, **kwargs), addr)
        logging.info("Sent response")

    def start_threaded(self):
        logging.info(f"Threaded DNS Server running at {host[0]}:{host[1]}")
        while True:
            try:
                # Recieve packet
                buf, addr = self.sock.recvfrom(512)

                # Create thread for response (sends back in self.threaded_handle_dns_query)
                client_thread = threading.Thread(target=self.threaded_handle_dns_query, args=(addr, buf))
                # Start thread
                client_thread.start()
            except Exception as e:
                # Handle errors, but keep the program running
                self.done()
                logging.error("Error", exc_info=1)
                
    def start(self):
        logging.info(f"DNS Server running at {host[0]}:{host[1]}")
        while True:
            try:
                buf, addr = self.sock.recvfrom(512)
                response = self.handle_dns_query(buf)
                self.sock.sendto(response, addr)
                logging.info("Sent response")
            except Exception as e:
                self.done()
                logging.error("Error", exc_info=1)
                
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple forwarding DNS server")
    parser.add_argument(
        "--host",
        "-a",
        required=True,
        type=str,
        help="The host address in the form of a.b.c.d:port",
    )
    parser.add_argument(
        "--resolver",
        "-r",
        required=True,
        type=str,
        help="The resolver address in the form of a.b.c.d:port",
    )
    parser.add_argument(
        "--redirect",
        "-R",
        required=True,
        type=str,
        help="The IP address to redirect to",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        type=str,
        default="DEBUG",
        help="Provide information about the logging level",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["default", "threaded"],
        type=str,
        help="Mode to run server in: threaded or not"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=args.loglevel.upper(),
        format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    host = args.host.split(":")
    resolver = args.resolver.split(":")
    redirect_ip = args.redirect


    manager = ServerManager(host=(host[0], int(host[1])), resolver_addr=(resolver[0], int(resolver[1])), blocklist=BLOCKLIST, redirect_ip=redirect_ip)

    if args.mode == "default":
        manager.start()
    elif args.mode == "threaded":
        manager.start_threaded()
