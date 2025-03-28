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

import readline
import socket
import sys


def main(addr: tuple[str, int], secret: str | None = None) -> None:
    """Start a shell client with cdns.

    Args:
        addr: Address of the server.
        secret: Secret of the server. Defaults to None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(addr)
    if secret is None:
        secret = input("Secret:")

    sock.sendall(secret.encode())

    try:
        while True:
            data = sock.recv(1024).decode()
            if not data:
                break

            sys.stdout.write(data)
            sys.stdout.flush()

            sock.send(sys.stdin.readline().encode())
    finally:
        sock.close()
