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
# SOFTWARE.

import concurrent.futures
import socket
import sys
from pathlib import Path

import line_profiler as lp
import timerit

from cdns.protocol import *
from cdns.resolvers import RecursiveResolver
from cdns.server.manager import ServerManager
from cdns.server.response import ResponseHandler
from cdns.server.storage import RecordStorage


def forward(query: bytes) -> concurrent.futures.Future[bytes]:
    future = concurrent.futures.Future()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("1.1.1.1", 53))
    response, _ = sock.recvfrom(512)

    sock.close()
    future.set_result(response)
    return future


# This is what the server decodes when using dig
# $ dig @127.0.0.1 -p 2053 google.com
query = pack_all_compressed(
    DNSHeader(
        id_=62967,
        qr=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=2,
        rcode=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=1,
    ),
    [DNSQuestion(decoded_name="example.com", type_=1, class_=1)],
)

storage = RecordStorage()
storage.load_zones_from_dir(Path("./example-zones").resolve())
manager = ResponseHandler(
    storage=storage, resolver=forward, tcp_conn="foo"  # No sending
)


def _send():
    return None


# We don't need send
manager.send = _send


def time_lines():
    p = lp.LineProfiler()

    manager.receive(query)

    p.add_function(manager.process)
    p.add_function(manager.storage.get_record.__wrapped__)

    p.enable()
    manager.process()
    p.disable()

    p.print_stats()


def time_it():
    manager.receive()

    for _ in timerit:
        manager.process()


def time_socket():
    manager.resolver_socket_addr = ("127.0.0.1", 2053)
    # Assume server is hosted at 127.0.0.1:2053
    for _ in timerit:
        manager.forward_dns_query(query)


def time_extractors():
    from publicsuffix2 import get_sld
    from publicsuffixlist import PublicSuffixList
    from tldextract import TLDExtract

    psl = PublicSuffixList()
    e = TLDExtract(cache_dir="../exctractor.cache")

    p = lp.LineProfiler()
    p.add_function(get_sld)
    p.add_function(psl.privatesuffix)
    p.add_function(e.extract_str)

    p.enable()

    get_sld("foo.a.google.com")
    psl.privatesuffix("foo.a.google.com")
    e.extract_str("foo.a.google.com")

    p.disable()
    p.print_stats()


def t():
    def do():
        sys.getsizeof("abcdef")
        sys.getsizeof(1)
        sys.getsizeof([])

    p = lp.LineProfiler()
    p.add_function(do)

    p.enable()

    do()

    p.disable()
    p.print_stats()


def q():
    query = DNSQuery(DNSHeader(), [DNSQuestion(decoded_name="google.com")])

    p = lp.LineProfiler()

    p.add_function(concurrent.futures.Future.result)

    p.enable()

    r = RecursiveResolver()
    f = r.send(query.pack())
    f.result()

    p.disable()
    p.print_stats()


q()

if __name__ == "__main__":
    if "-l" in sys.argv:
        time_lines()
    elif "-t" in sys.argv:
        time_it()
    elif "-s" in sys.argv:
        time_socket()
    elif "-e" in sys.argv:
        time_extractors()

    # manager.done()
