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

import socket
import time
from multiprocessing import Process, Queue

from .protocol import DNSHeader, DNSQuestion, pack_all_compressed, unpack_all

test_query = pack_all_compressed(
    DNSHeader(id_=1, qdcount=1), [DNSQuestion(decoded_name="github.com")]
)

servers = [
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "8.8.8.8",
    "8.8.4.4",
    "208.67.222.222",
    "208.67.220.220",
]

servers = [(ip, 53) for ip in servers]


class GetResolverDaemon(Process):
    def __init__(
        self,
        servers: list[tuple[str, int]],
        interval: int,
        queue: Queue,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        # self.servers = servers
        # self.latencies = [0] * len(servers)s
        self.servers = {k: 0 for k in servers}
        self.total_agg = 0

        self.queue = queue

        self.interval = interval
        self.last_time = None

        self.test_query = test_query

    def latency(self, addr, iterations=3):
        latencies = []
        for i in range(iterations):
            try:
                start = time.time()

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(self.test_query, addr)
                    data, addr = sock.recvfrom(512)

                    latencies.append(time.time() - start)

            except (socket.timeout, OSError):
                latencies.append(float("inf"))
        return sum(latencies) / iterations

    def find_fastest_server(self):
        if self.total_agg == 0:
            self.servers = {k: 0 for k in list(self.servers.keys())}

        for key in list(self.servers.keys()):
            l = self.latency(key)
            self.servers[key] = (self.servers[key] + l) / 2

        self.total_agg += 1
        if self.total_agg > 5:
            self.total_agg = 0

        return min(self.servers, key=self.servers.__getitem__)

    def run(self):
        if self.last_time is None:
            server = self.find_fastest_server()
            self.queue.put(server)

            self.last_time = time.time()
        while True:
            now = time.time()
            wait_t = (self.last_time + self.interval) - now
            if wait_t > 0:
                time.sleep(wait_t)

            self.last_time = now

            server = self.find_fastest_server()
            self.queue.put(server)


if __name__ == "__main__":
    q = Queue()
    d = GetResolverDaemon(servers, 1, q)
    d.start()
    while True:
        if not q.empty():
            print(q.get())
    #  print(GetResolverDaemon(Queue()).latency(("1.1.1.1", 53)))
