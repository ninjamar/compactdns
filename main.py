#!/usr/bin/env python3

# dns-server
# A simple forwarding DNS server
# https://github.com/ninjamar/dns-server
# Version 0.0.1

import socket
import struct
from dataclasses import dataclass


def encode_name_simple(name: str) -> bytes:
    labels = name.split(".")
    encoded = [bytes([len(label)]) + label.encode("ascii") for label in labels]
    return b"".join(encoded) + b"\x00"


def decode_name_simple(buf: bytes) -> str:
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


@dataclass
class DNSHeader:
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
    def from_buffer(cls, buf):
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


@dataclass
class DNSQuestion:
    decoded_name: str = ""

    type_: int = 1  # TODO: BUILTIN
    class_: int = 1

    def pack(self, encoded_name) -> bytes:
        return encoded_name + struct.pack("!HH", self.type_, self.class_)

@dataclass
class DNSAnswer:
    decoded_name: str = ""
    type_: int = 1
    class_: int = 1
    ttl: int = 0
    rdlength: int = 4
    rdata: str = ""  # IPV4

    def __post_init__(self):
        self.rdata = struct.pack("!4B", *[int(x) for x in self.rdata.split(".")])

    def pack(self, encoded_name):
        return (
            encoded_name
            + struct.pack(
                "!HHIHH",
                self.type_,
                self.class_,
                self.ttl,
                self.rdlength,
                len(self.rdata),
            )
            + self.rdata
        )


def pack_all_uncompressed(
    header: DNSHeader, questions: list[DNSQuestion], answers: list[DNSAnswer]
):
    response = header.pack()
    for question in questions:
        response += question.pack(encode_name_simple(question.decoded_name))
    for answer in answers:
        response += answer.pack(encode_name_simple(answer.decoded_name))
    return response


def pack_all_compressed(
    header: DNSHeader, questions: list[DNSQuestion] = [], answers: list[DNSAnswer] = []
):
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
            encoded_name = encode_name_simple(question.decoded_name)
            name_offset_map[question.decoded_name] = len(response)

        response += question.pack(encoded_name)

    for answer in answers:
        if answer.decoded_name in name_offset_map:
            # Starting pointer + offset of name
            pointer = 0xC000 | name_offset_map[answer.decoded_name]

            encoded_name = struct.pack("!H", pointer)
        else:
            encoded_name = encode_name_simple(answer.decoded_name)
            name_offset_map[answer.decoded_name] = len(response)

        response += answer.pack(encoded_name)
    return response


def decode_domain(buf: bytes, start_idx: int) -> str:
    labels = []
    idx = start_idx
    visited = set()  # prevent going into a loop

    while True:
        if idx in visited:
            raise Exception("Unable to decode domain: loop detected")
        visited.add(idx)

        length = buf[idx]
        if length == 0:  # null terminator
            idx += 1
            break
        elif length & 0xC0 == 0xC0:  # pointer
            pointer = struct.unpack("!H", buf[idx : idx + 2])[0] & 0x3FFF
            domain, _ = decode_domain(buf, pointer)
            labels.append(domain)

            idx += 2
            break
        else:
            labels.append(buf[idx + 1 : idx + 1 + length].decode("ascii"))
            idx += 1 + length

    return ".".join(labels), idx


def unpack_all(buf):
    header = DNSHeader.from_buffer(buf[:12])  # First 12 bytes are header

    idx = 12  # start after header

    questions = []

    for _ in range(header.qdcount):
        decoded_name, idx = decode_domain(buf, idx)
        type_, class_ = struct.unpack("!HH", buf[idx : idx + 4])
        idx += 4

        questions.append(
            DNSQuestion(decoded_name=decoded_name, type_=type_, class_=class_)
        )

    return header, questions


# TODO: Unpack all
def forward_dns_query(query: bytes, resolver: tuple) -> bytes:
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.sendto(query, resolver)

    response, _ = resolver_socket.recvfrom(512)
    resolver_socket.close() # should i use the same socket?
    return response

def handle_dns_query(buf: bytes, resolver: tuple) -> bytes:
    header, questions = unpack_all(buf)

    # process header, questions

    print(header, questions)
    # repack data
    send = pack_all_compressed(header, questions)
    response = forward_dns_query(send, resolver)
    
    print(unpack_all(response))
    # Update id qcount etc
    return response


def server(resolver):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = handle_dns_query(buf, resolver)

            udp_socket.sendto(response, source)
        except Exception as e:
            raise e
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    server(("1.1.1.1", 53))
