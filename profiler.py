import socket
import sys

import line_profiler as lp
import timerit

from cdns import *

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
    [DNSQuestion(decoded_name="github.com", type_=1, class_=1)],
)
blocklist = load_all_blocklists(["example-blocklists/lowe.txt"], 300)
manager = ServerManager(
    host=("127.0.0.1", 8080),  # Not needed
    resolver=("1.1.1.1", 53),  # Needed
    blocklist=blocklist,  # Profile with 3538 rules
)


def time_lines():
    p = lp.LineProfiler()
    p.add_function(manager.handle_dns_query)
    p.enable()
    manager.handle_dns_query(query)
    p.disable()
    p.print_stats()


def time_it():
    for _ in timerit:
        manager.handle_dns_query(query)


def time_socket():
    manager.resolver_socket_addr = ("127.0.0.1", 2053)
    # Assume server is hosted at 127.0.0.1:2053
    for _ in timerit:
        manager.forward_dns_query(query)


if __name__ == "__main__":
    if "-l" in sys.argv:
        time_lines()
    elif "-t" in sys.argv:
        time_it()
    elif "-s" in sys.argv:
        time_socket()

    manager.done()
