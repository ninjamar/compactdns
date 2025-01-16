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


DEFAULT_BLOCKING_TTL = 60

# TODO: Ensure all code is right (via tests)
# TODO: Document the archictecture (comments)

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
    # extract size, parse section, until null
    while buf[idx] != 0x00:
        size = buf[idx]
        idx += 1
        label = buf[idx : idx + size]
        labels.append(label.decode("ascii"))
        idx += size
    return ".".join(labels)


def decode_name(buf: bytes, start_idx: int) -> tuple[str, int]:
    """Decode a name, that is compressed, from a buffer

    :param buf: buffer containing name
    :type buf: bytes
    :param start_idx: start index of name
    :type start_idx: int
    :raises Exception: infinite loop
    :return: decoded name, index
    :rtype: tuple[str, int]
    """
    labels = []
    idx = start_idx
    visited = set()  # prevent going into a loop

    while idx < len(buf):
        if idx in visited:
            raise Exception("Unable to decode domain: loop detected")
        visited.add(idx)

        label_len = buf[idx]
        if label_len == 0:  # null terminator
            # idx += 1
            break
        elif label_len & 0xC0 == 0xC0:  # pointer
            # pointer = struct.unpack("!H", buf[idx : idx + 2])[0] & 0x3FFF
            pointer = ((label_len & 0x3F) << 8) + buf[idx + 1]
            domain, _ = decode_name(buf, pointer)
            labels.append(domain)

            # idx += 2
            break
        labels.append(buf[idx + 1 : idx + 1 + label_len].decode("ascii"))
        idx += label_len + 1

    return ".".join(labels), idx

@dataclasses.dataclass
class DNSHeader:
    """Dataclass to store DNS header"""

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

    decoded_name: str = ""

    type_: int = 1  # TODO: BUILTIN
    class_: int = 1

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS question

        :param encoded_name: encoded name
        :type encoded_name: bytes
        :return: packed DNS question
        :rtype: bytes
        """
        return encoded_name + struct.pack("!HH", self.type_, self.class_)


@dataclasses.dataclass
class DNSAnswer:
    """Dataclass to store DNS answer"""

    decoded_name: str = ""
    type_: int = 1
    class_: int = 1
    ttl: int = 0
    rdlength: int = 4
    rdata: str = ""  # IPV4

    def __post_init__(self):
        # self.rdata = struct.pack("!4B", *[int(x) for x in self.rdata.split(".")])
        pass

    def pack(self, encoded_name: bytes) -> bytes:
        """Pack the DNS answer

        :param encoded_name: name encoded
        :type encoded_name: bytes
        :return: packed DNS answer
        :rtype: bytes
        """
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
    response = header.pack()
    for question in questions:
        response += question.pack(encode_name_uncompressed(question.decoded_name))
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
    response = header.pack()

    name_offset_map = {}

    # Compress question + answers

    # Pack answers + store names + compression
    for question in questions:
        if question.decoded_name in name_offset_map:
            # Starting pointer + offset of name
            pointer = 0xC000 | name_offset_map[answer.decoded_name]

            encoded_name = struct.pack("!H", pointer)
        else:
            encoded_name = encode_name_uncompressed(question.decoded_name)
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
    header = DNSHeader.from_buffer(buf[:12])  # First 12 bytes are header

    idx = 12  # start after header

    questions = []

    for _ in range(header.qdcount):
        decoded_name, idx = decode_name(buf, idx)

        type_, class_ = struct.unpack("!HH", buf[idx : idx + 4])
        idx += 4

        questions.append(
            DNSQuestion(decoded_name=decoded_name, type_=type_, class_=class_)
        )

    answers = []
    for _ in range(header.ancount):
        decoded_name, idx = decode_name(buf, idx)

        type_, class_ = struct.unpack("!HH", buf[idx : idx + 4])
        idx += 4

        ttl = struct.unpack("!I", buf[idx : idx + 4])[0]
        idx += 4

        rdlength = struct.unpack("!H", buf[idx : idx + 2])[0]
        idx += 2


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

    return (header, questions) if header.ancount == 0 else (header, questions, answers)


def forward_dns_query(query: bytes, addr: tuple[str, int]) -> bytes:
    """Forward a DNS query to an address

    :param query: query to forward
    :type query: bytes
    :param addr: tuple containing address and port
    :type addr: tuple[str, int]
    :return: response from the server
    :rtype: bytes
    """
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.sendto(query, addr)

    response, _ = resolver_socket.recvfrom(512)
    resolver_socket.close()  # should i use the same socket?
    return response


def handle_dns_query(
    buf: bytes, resolver: tuple[str, int], blocklist: set[str]
) -> bytes:
    """Handle a DNS query

    :param buf: buffer containing DNS query
    :type buf: bytes
    :param resolver: forwarding server address and port
    :type resolver: tuple[str, int]
    :return: response from server
    :rtype: bytes
    """
    logging.info("Received query")

    header, questions = unpack_all(buf)
    print("Questions", questions)

    logging.debug(f"Received query: {header}, {questions}")

    new_header = dataclasses.replace(header)
    new_questions = []
    questions_index_blocked = []

    # remove blocked sites from dns forward
    for idx, question in enumerate(questions):
        if question.decoded_name in blocklist:
            questions_index_blocked.append(idx)
        else:
            new_questions.append(question)

    print("Blocked questions index", questions_index_blocked)
    print("Blocked questions", [questions[i] for i in questions_index_blocked])



    new_header.qdcount = len(new_questions)

    print("New header", new_header)
    print("New questions", new_questions)

    if new_header.qdcount > 0:
        # process header, questions
        # repack data
        send = pack_all_compressed(new_header, new_questions)
        print(send)
        response = forward_dns_query(send, resolver)

        logging.debug("Received query from dns server")

        # re add blocked sites to response, using blocked page as ip address
        recv_header, recv_questions, recv_answers = unpack_all(response)
    else:
        recv_header = new_header
        recv_questions = new_questions
        recv_answers = []

    # print("Recieved answers", recv_answers)

    for idx in questions_index_blocked:
        info = questions[idx]
        answer = DNSAnswer(
            decoded_name=info.decoded_name,
            type_=info.type_,
            class_=info.type_,
            ttl=DEFAULT_BLOCKING_TTL,
            rdlength=4,
            # inet_aton encodes a ip address into bytes
            rdata=socket.inet_aton("127.0.0.1"),  # TODO: Use class, and cache.
            # rdata="127.0.0.1"
        )

        # Obviously isn't going to work
        recv_questions.insert(idx, info)
        recv_answers.insert(idx, answer)

    recv_header.qdcount = len(recv_questions)
    recv_header.ancount = len(recv_answers)

    logging.info(f"Sending query back, {recv_header}, {recv_questions}, {recv_answers}")
    # Update id qcount etc
    return pack_all_compressed(recv_header, recv_questions, recv_answers)


def server(host: tuple[str, int], resolver: tuple[str, int]) -> None:
    """Start the DNS forwarding server

    :param host: host address and port
    :type host: tuple[str, int]
    :param resolver: resolver address and port
    :type resolver: tuple[str, int]
    """
    logging.info("Starting DNS Server")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(host)
    logging.info(f"DNS Server running at {host[0]}:{host[1]}")

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = handle_dns_query(buf, resolver, ["google.com"])
            print(response)

            udp_socket.sendto(response, source)
        except Exception as e:
            raise e
            print(f"Error receiving data: {e}")
            break


def main():
    parser = argparse.ArgumentParser(description="A simple forwarding DNS server")
    parser.add_argument(
        "--host",
        required=True,
        type=str,
        help="The host address in the form of a.b.c.d:port",
    )
    parser.add_argument(
        "--resolver",
        required=True,
        type=str,
        help="The resolver address in the form of a.b.c.d:port",
    )

    args = parser.parse_args()

    host = args.host.split(":")
    resolver = args.resolver.split(":")

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    server((host[0], int(host[1])), (resolver[0], int(resolver[1])))
if __name__ == "__main__":
    main()


# TODO: Use a class
# Port: 2053
# Test with multiple questions
# Custom block page/server