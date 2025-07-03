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

import base64
import dataclasses
from http.client import HTTPMessage, parse_headers
from io import BufferedReader, BytesIO
from urllib.parse import parse_qs, urlsplit


@dataclasses.dataclass
class HTTPRequest:
    buf: bytes = b""

    method: str = ""
    path: str = ""
    version: str = ""
    headers: HTTPMessage = None

    body: bytes = None


def parse_req(buf: bytes) -> HTTPRequest:
    buf = BufferedReader(BytesIO(buf))

    req_line = buf.readline().decode("iso-8859-1").rstrip("\r\n")

    try:
        method, path, version = req_line.split(" ", maxsplit=2)
    except:
        raise ValueError(f"Invalid HTTP request line: {req_line}")  # TODO: use !r

    method = method.upper()  # post -> POST

    headers = parse_headers(buf)  # consumes until body

    return HTTPRequest(
        buf,
        method,
        path,
        version,
        headers,
    )


# Utilities for DNS over HTTPS (DoH)
def parse_doh(req: HTTPRequest):
    body = None
    if req.method == "POST":
        length = req.headers.get("Content-Length")
        if length is None:
            raise ValueError("POST missing Content-Length header")
        length = int(length)

        body = req.buf.read(length)  # read length bytes

    payload = None
    if req.method == "POST":
        # For POST, the payload is the body
        payload = body

    elif req.method == "GET":
        # url?dns=<base64encoded>
        parts = urlsplit(req.path)
        qs = parse_qs(parts.query)  # get dict of url params
        data = qs.get("dns")[0]
        if not data:
            raise
        # This format excludes padding to increase space
        n = len(data)
        # get number of padding (round up) to get multiple of 4
        padding = "=" * (-n % 4)
        payload = base64.urlsafe_b64decode(data + padding)

    else:
        raise

    return req.path, payload


def make_response(req: HTTPRequest, buf: bytes):
    return (
        f"{req.version} 200 OK\r\n"
        f"Content-Type: application/dns-message\r\n"
        f"Content-Length: {len(buf)}\r\n",
        "\r\n",
    ).encode(
        "utf-8"
    ) + buf  # to bytes


if __name__ == "__main__":
    raw = (
        b"POST /dns-query HTTP/1.1\r\n"
        b"Host: dns.example.com\r\n"
        b"Content-Type: application/dns-message\r\n"
        b"Content-Length: 12\r\n"
        b"\r\n"
        b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78"
    )
    raw = (
        b"GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\r\n"
        b"Host: dns.example.com\r\n"
        b"Accept: application/dns-message\r\n"
        b"\r\n"
    )

    req = parse_doh(raw)
    print(req)
