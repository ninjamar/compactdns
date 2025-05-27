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
        
        logging.error("Adding item to tracker")

        with lock:
            self[hash(target)] = time.time()

    def end(self, target, *args, **kwargs):
        if not target:
            raise TypeError("Need a valid target")
        
        logging.error("Removing item from tracker")
        with lock:
            del self[hash(target)]

    def get_elapsed(self):
        return {k: time.time() - v for k, v in self.items()}

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
        return LCBMetaclass("Foo", (BaseFoo, ), {}, mixins=[ResourceTrackerMixin(tracker)])
    
    tracker = {}
    f = make_foo(tracker)
    