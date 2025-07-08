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
import selectors
import socket
import ssl
import struct
import threading
from collections import namedtuple
from enum import Enum
from typing import cast

from cdns.protocol import *

from .tcp import TCPForwarder, states as _states


class states(_states):
    ssl_handshake = 6


class TLSForwarder(TCPForwarder):
    # TCP Forwarder but with SSL layer
    def __init__(self):
        super().__init__()

    def forward(self, query, addr):
        return super().forward(query, addr)

    def _thread_handler(self):
        return super()._thread_handler()

    def cleanup(self):
        return super().cleanup()

    def _cleanup_sock(self, sock):
        return super()._cleanup_sock(sock)

    def _sock_writeable(self, sock, ctx):
        return super()._sock_writeable(sock, ctx)

    def _sock_readable(self, sock, ctx):
        return super()._sock_readable(sock, ctx)
    
