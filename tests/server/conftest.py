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

import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from cdns.cli.kwargs import get_kwargs
from cdns.client import Client
from cdns.protocol import *
from cdns.server.manager import ServerManager

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


def run_server(config_path):
    kwargs = get_kwargs(config_path)

    # Need to put config path, zone_path, doh path and ssl path
    # We need to use temporary files to do all the things because paths to files are expected
    server = ServerManager.from_config(kwargs)
    server.start()


def make_keypairs():
    if not os.path.isdir(TMP_PATH):
        os.mkdir(TMP_PATH)

    # if os.path.exists(SERVER_LOG_PATH):

    for pair in KEY_CERT_PAIRS:
        # subj default values
        subprocess.check_call(
            f'openssl req -x509 -newkey rsa:4096 -keyout {pair[0]} -out {pair[1]} -days 365 -nodes -subj "/"',
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


# Also need to check which directory structure to use
# https://docs.pytest.org/en/stable/explanation/goodpractices.html#choosing-a-test-layout
@pytest.fixture(scope="session")
def dns_server():

    # TODO: This should probably be run only once per session. If scope for tests
    # cange, then make sure
    make_keypairs()
    process = multiprocessing.Process(
        target=run_server, args=(str(CONFIG_PATH),), daemon=True
    )
    process.start()

    # HACK: Add health check
    time.sleep(1)

    # Execution before yielding is the startup. Execution after is the teardown
    yield

    process.terminate()
    process.join()
