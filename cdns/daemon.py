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

import signal
import socket
import time
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Callable

from .protocol import DNSHeader, DNSQuery, DNSQuestion


class BaseDaemon(Process):
    """All daemons inherit from this class."""

    def __init__(self, interval, queue: "Queue | None", *p_args, **p_kwargs):
        # waht. Queue | None fails, but putting quotes around or using Optional[Queue] works
        # Seems that Queue is a bound method (https://github.com/python/cpython/blob/main/Lib/multiprocessing/context.py#L100)
        #     def foo(q: Queue | None):
        #       ~~~~~~^~~~~~
        # TypeError: unsupported operand type(s) for |: 'method' and 'NoneType'

        """Create an instance of BaseDaemon.

        Args:
            queue: The Queue to use. If there is no queue, make one. Defaults to None.
            *p_args: Args to the Process.
            *p_kwargs: Kwargs to the Process.
        """
        super().__init__(*p_args, **p_kwargs)

        self._interval = interval

        if not queue:
            self.queue: Queue = Queue()
        else:
            self.queue = queue

        self._last_time = None

    def run(self):
        """Run the daemon."""
        # signal.signal(signal.SIGINT, signal.SIG_IGN)

        # if self.last_time is None:
        self.queue.put(self.task())

        self._last_time = time.time()
        while True:
            now = time.time()
            wait_t = (self._last_time + self._interval) - now
            if wait_t > 0:
                time.sleep(wait_t)

            self.queue.put(self.task())

            self._last_time = now

    def task(self):
        raise NotImplementedError


class FastestResolverDaemon(BaseDaemon):
    def __init__(
        self, servers: list[tuple[str, int]], test_name="github.com", **kwargs
    ) -> None:
        """Daemon to find the fastest resolver.

        Args:
            servers: A list of DNS servers to find.
            interval: Interval to check DNS servers.
            test_name: Test name for the query. Defaults to "github.com".
            **kwargs: Passed to BaseDaemon.
        """
        super().__init__(**kwargs)  # TODO: Create Queue inside BaseDaemon

        self.servers = {k: 0.0 for k in servers}
        self.total_agg = 0

        self.test_query = DNSQuery(
            DNSHeader(id_=1, qdcount=1), [DNSQuestion(decoded_name=test_name)]
        ).pack()

    def latency(self, addr, iterations=3) -> float:
        """Get the latency to a server.

        Args:
            addr: Address of server.
            iterations: Number of times to check. Defaults to 3.

        Returns:
            The latency in seconds.
        """
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

    def find_fastest_server(self) -> tuple[str, int]:
        """Get the fastest server.

        Returns:
            The fastest server.
        """
        if self.total_agg == 0:
            self.servers = {k: 0.0 for k in list(self.servers.keys())}

        for key in list(self.servers.keys()):
            l = self.latency(key)
            self.servers[key] = (self.servers[key] + l) / 2

        self.total_agg += 1
        if self.total_agg > 5:
            self.total_agg = 0

        return min(self.servers, key=self.servers.__getitem__)

    def task(self):
        return self.find_fastest_server()


"""
if __name__ == "__main__":
    
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

    q = Queue()
    d = FastestResolverDaemon(servers, 1, q)
    d.start()
    while True:
        if not q.empty():
            print(q.get())
    #  print(FastestResolverDaemon(Queue()).latency(("1.1.1.1", 53)))

"""
