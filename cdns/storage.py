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

import os
from pathlib import Path
from .zones import DNSZone
from .cache import TimedCache

class RecordStorage:
    def __init__(self):
        # Store a TimedCache for upstream requests
        # Lookup zones locally
        self.cache = TimedCache()
        self.zones = []
    
    @classmethod
    def from_pickle(cls):
        pass

    def add_zone(self):
        pass
    def load_zones_from_files(self):
        pass

    def load_cache_from_file():
        pass
    
    def write_cache_to_file():
        pass

    @classmethod
    def from_directory(cls, zone_dir_path: str, cache_dir_path: str):
        zone_dir_path = Path(zone_dir_path).resolve()
        cache_dir_path = Path(cache_dir_path).resolve()

        zone_paths = [zone_dir_path + "/"+ x for x in os.listdir(zone_dir_path) if x.endswith(".zone")]
        cache_paths = [cache_dir_path + "/"+ x for x in os.listdir(cache_dir_path) if x.endswith(".zone")]