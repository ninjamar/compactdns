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

import concurrent.futures
import ipaddress

import pytest

from cdns.client import Client
from cdns.protocol import *

SERVER_ADDR = ("127.0.0.1", 2053)


@pytest.fixture(scope="session")
def client():
    client = Client()

    try:
        yield client

    finally:
        client.cleanup()


def get_queries():
    queries = []

    # Test UDP
    queries += [(DNSQuery(questions=[DNSQuestion(decoded_name="google.com")]), "udp")]

    # Test cache
    queries += [(DNSQuery(questions=[DNSQuestion(decoded_name="google.com")]), "udp")]

    queries += [(DNSQuery(questions=[DNSQuestion(decoded_name="google.com")]), "tcp")]

    queries += [(DNSQuery(questions=[DNSQuestion(decoded_name="google.com")]), "tls")]
    queries += [(DNSQuery(questions=[DNSQuestion(decoded_name="google.com")]), "doh")]

    return queries


def submit_futures(
    client: Client, server_addr: tuple[str, int]
) -> list[concurrent.futures.Future[DNSQuery]]:
    return [
        client.resolve(query, method, server_addr) for (query, method) in get_queries()
    ]


def is_ip(test):
    try:
        ipaddress.ip_address(test)
        return True
    except ValueError:
        return False


def test_batch(dns_server, client):

    futures = submit_futures(client, SERVER_ADDR)

    done, not_done = concurrent.futures.wait(futures, timeout=10)

    assert not not_done, f"Queries did not finish execution: {not_done}"

    for future in done:
        assert is_ip(future.result().answers[0].decoded_rdata)
