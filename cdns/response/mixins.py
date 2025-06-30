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

import logging
import time
import threading
from cdns.lcb import LCBMetaclass, LCBMethods, BaseMixin

from cdns.protocol import *

__all__ = ["ResourceTrackerMixin", "_TestMixin"]

lock = threading.Lock()


class ResourceTrackerMixin(dict, BaseMixin):
    """
    Mixin for a resource tracker.
    """

    def __init__(self):
        super().__init__()
        # self.tracker = tracker # dict

    def start(self, target, *args, **kwargs):
        if not target:
            raise TypeError("Need a valid target")

        logging.debug("Adding item to tracker")

        with lock:
            self[hash(target)] = time.time()

    def end(self, target, *args, **kwargs):
        if not target:
            raise TypeError("Need a valid target")

        logging.debug("Removing item from tracker")
        with lock:
            del self[hash(target)]

    def get_elapsed(self):
        return {k: time.time() - v for k, v in self.items()}


class SmartEnsureLoadedMixin(BaseMixin):
    # TODO: This is broken and will cause a big issue -- the culprit is infinite triggering
    def __init__(self, target_queue):
        raise NotImplementedError  # Make sure does not start
        super().__init__()

        # host to time
        self.interval = 300  # 5 minutes
        self.hit_threshold = 2
        self.active: dict[str, list[int, int]] = {}
        # host -> [time_of_last_hit, hits]

        self.target_queue = target_queue

    def start(self, target, *args, **kwargs):
        pass

    def end(self, target, *args, **kwargs):
        query: DNSQuery = target.buf

        for question in query.questions:
            if question.decoded_name not in self.active:
                self.active[question.decoded_name] = [time.time(), 1]
            else:
                self.active[question.decoded_name][0] = time.time()
                self.active[question.decoded_name][1] += 1

        logging.info("Active %s", self.active)
        self.target_queue.put(self.get_top())

    def get_top(self) -> list[tuple[str, int]]:

        top = []
        now = time.time()

        for decoded_name, [last_hit_time, hits] in list(
            self.active.items()
        ):  # make a copy
            # Check if recently used
            if now - last_hit_time <= self.interval:
                if hits >= self.hit_threshold:
                    top.append((decoded_name, hits))
            else:  # expire old items
                del self.active[decode_name]

        top = sorted(top, key=lambda x: x[1], reverse=True)
        print(top)
        return top


class _TestMixin(BaseMixin):
    def start(self, target, *args, **kwargs):
        pass

    def end(self, target, *args, **kwargs):
        pass


if __name__ == "__main__":

    class BaseFoo(LCBMethods):
        def __init__(self):
            self.lc_start()

        def done(self):
            self.lc_end()

    def make_foo(tracker):
        return LCBMetaclass(
            "Foo", (BaseFoo,), {}, mixins=[ResourceTrackerMixin(tracker)]
        )

    tracker = {}
    f = make_foo(tracker)
