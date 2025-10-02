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
import tempfile
import os
import sys
import time
import subprocess
from pathlib import Path
from cdns.server.manager import ServerManager
from cdns.cli.kwargs import get_kwargs
from cdns.protocol import *
from cdns.client import Client


root_path = Path(__file__).parent.resolve()

# Config path
CONFIG_PATH = (root_path / "config.toml").resolve()

TMP_PATH = (root_path / "tmp").resolve()
SERVER_LOG_PATH = (root_path / "tmp" / "server.log").resolve()
KEY_CERT_PAIRS = [
    (
        (root_path / "tmp" / "key.pem").resolve(),
        (root_path / "tmp" / "cert.pem").resolve(),
    ),
    (
        (root_path / "tmp" / "dohkey.pem").resolve(),
        (root_path / "tmp" / "dohcert.pem").resolve(),
    ),
]

CHECK_STR = "DNS Server running at 127.0.0.1:8443 via DNS over HTTPS"


class TestClientServer:
    def spawn_server(self):
        if not os.path.isdir(TMP_PATH):
            os.mkdir(TMP_PATH)

        #if os.path.exists(SERVER_LOG_PATH):
        #    SERVER_LOG_PATH.unlink()
        
        #os.mkfifo(SERVER_LOG_PATH)

        for pair in KEY_CERT_PAIRS:
            # subj default values
            subprocess.check_call(
                f'openssl req -x509 -newkey rsa:4096 -keyout {pair[0]} -out {pair[1]} -days 365 -nodes -subj "/"',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


        print("Waiting for server to start")
        # Wait until server has written started into log file
        self.process = subprocess.Popen([sys.executable, str(root_path / "spawn_server.py"), str(CONFIG_PATH)])

        with open(SERVER_LOG_PATH, "r") as f:

            for line in f:
                if CHECK_STR in line:
                    break

        print("Server started!")

    def shutdown_server(self):
        print("Killing server")
        self.process.kill()
        print("Server killed")


if __name__ == "__main__":
    """
    q = DNSQuery(questions=[DNSQuestion(decoded_name="google.com")])

    c = Client()

    f = c.resolve(q, "udp", ("127.0.0.1", 2053))
    print(f.result())

    c.cleanup()
    """
    test = TestClientServer()
    test.spawn_server()
    time.sleep(1)
    test.shutdown_server()
