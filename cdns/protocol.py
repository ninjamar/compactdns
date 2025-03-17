# compactdns
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
"""
A module implementing RFC1035, the DNS protocol specification.
=============
cdns.protocol
=============

This module implements the DNS protocol as defined by RFC1035
(https://www.rfc-editor.org/rfc/rfc1035). Note that this module hasn't
been tested for full conformity.


Headers, Questions, and Answers
===============================
These are all represented by the corresponding dataclass.

>>> DNSHeader(**fields)
>>> DNSQuestion(**fields)
>>> DNSAnswer(**fields)

Each field, except for `decoded_name`, corresponds to what RFC1035 says. Please
note that `id`, `class`, and `type` are all represented by `id_`, `class_`, and
`type_` respectively. Also, fields stored as bytes such as `rdata` are assumed
to be already encoded. Each dataclass has a pack method, which packs the
dataclass into the DNS wire format. `DNSQuestion.pack` and `DNSAnswer.pack` both
take encoded_name as an argument. This is because the field can be compressed
depending on other packets.

>>> DNSHeader(
...         id_=12345,
...         qr=1,
...         opcode=0,
...         aa=0,
...         tc=0,
...         rd=1,
...         ra=1,
...         z=0,
...         rcode=0,
...         qdcount=1,
...         ancount=1,
...         nscount=0,
...         arcount=0
...     ).pack()
b'09\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

>>> DNSQuestion(decoded_name="google.com", type_=1, class_=1).pack(
...     auto_encode_label("google.com"))
b'\x06google\x03com\x00\x00\x01\x00\x01'

>>> DNSAnswer(decoded_name="google.com", rdata=auto_encode_label("127.0.0.1"))
...     .pack(auto_encode_label("google.com"))
b'\x06google\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01'

Encoding/Decoding
=================

Most of these functions have the LRU cache applied.

Uncompressed name encoding/decoding
-----------------------------------

>>> encode_name_uncompressed("google.com")
b'\x06google\x03com\x00'
>>> decode_name_uncompressed(b'\x06google\x03com\x00')
'google.com'

Uncompressed generic encoding/decoding
--------------------------------------
>>> encode_label("IPV4", "127.0.0.1")
b'\x7f\x00\x00\x01'
>>> encode_label("IPV6", "::1")
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
>>> encode_label("LABEL", "google.com")
b'\x06google\x03com\x00'

decode_label has the same API, but takes encoded bytes instead of a string.

Automatic type detection for encoding/decoding
----------------------------------------------

Use `auto_encode_label` and `auto_decode_label` to automatically detect and
apply the correct encoding or decoding function.

Compressed encoding/decoding
----------------------------

Compressed encoding requires the whole packet. Use the packing/unpacking
functions instead. For decoding, use `decode_name`, which takes in a buffer,
and the index of the label.

>>> decode_name(b"some-really-long-buffer", 30)
"google.com"

Packing/Unpacking
=================

Packing
-------

>>> pack_all_uncompressed(DNSHeader, [DNSQuestion, ...], [DNSAnswer, ...])
b"a long uncompressed buffer"
>>> pack_all_compressed(DNSHeader, [DNSQuestion, ...], [DNSAnswer, ...])
b"a long compressed buffer"

Unpacking
---------

The function unpack_all handles both compressed and uncompressed buffers.
>>> unpack_all(b"a long buffer")
(DNSHeader, [DNSQuestion, ...], [DNSAnswer, ...])

"""

import dataclasses
import functools
import socket
import struct
from typing import Literal

from .utils import ImmutableBiDict

# Still need PTR, 12, SRV, 33, CAA, 257
RTypes = ImmutableBiDict(
    [
        ("A", 1),
        ("AAAA", 28),
        ("CNAME", 5),
        ("NS", 2),
        ("SOA", 6),
        ("MX", 15),
        ("TXT", 16),
    ],
)


@functools.lru_cache(maxsize=512)
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


@functools.lru_cache(maxsize=512)
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


@functools.lru_cache(maxsize=512)
def encode_label(type_: Literal["IPV4", "IPV6", "NAME", "LABEL"], label: str) -> bytes:
    """Encode a label according to it's type.

    Args:
        type_: Type of label.
        label: The label to encode.

    Returns:
        The encoded label.
    """
    # data, length
    if type_ == "IPV4":
        return socket.inet_aton(label)
    if type_ == "IPV6":
        return socket.inet_pton(socket.AF_INET6, label)
    if type_ == "NAME" or type_ == "LABEL":
        return encode_name_uncompressed(label)


@functools.lru_cache(maxsize=512)
def decode_label(type_: Literal["IPV4", "IPV6", "NAME", "LABEL"], label: bytes) -> str:
    """Decode a label according to it's type.

    Args:
        type_: The type of the label.
        label: The label to decode.

    Returns:
        The decoded label.
    """
    if type_ == "IPV4":
        return socket.inet_ntoa(label)
    if type_ == "IPV6":
        return socket.inet_ntop(socket.AF_INET6, label)
    if type_ == "NAME" or type_ == "LABEL":
        return decode_name_uncompressed(label)


@functools.lru_cache(maxsize=512)
def auto_encode_label(label):
    """Encode a label, automatically detecting it's type.

    Args:
        label: The label to encode.

    Returns:
        The encoded label.
    """
    if all(x.isdigit() for x in label.replace(".", "")):
        type_ = "IPV4"
    elif ":" in label:
        type_ = "IPV6"
    else:
        type_ = "LABEL"
    return encode_label(type_, label)


@functools.lru_cache(maxsize=512)
def auto_decode_label(label):
    """Decode a label, automatically detecting it's type.

    Args:
        label: The label to decode.

    Raises:
        Exception: Unable to automatically detect the type.

    Returns:
        The decoded label.
    """
    try:
        return decode_label("LABEL", label)
    except Exception as e:
        if len(label) == 4:
            return decode_label("IPV4", label)
        elif len(label) == 16:
            return decode_label("IPV6", label)
        # raise e
        raise Exception("Unable to decode label", e)


class DNSDecodeLoopError(Exception):
    """An exception if a loop is encountered while encoding a DNS query."""

    pass


# No cache here since it will size up really fast
# @functools.lru_cache(maxsize=512)
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
        # print(self.type_, self.class_, self.ttl_, self.rdlength_)
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


# TODO: Cache these because list isn't hashable
# @functools.lru_cache(maxsize=512)
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


# @functools.lru_cache(maxsize=512)
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


# @functools.lru_cache(maxsize=512)
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
