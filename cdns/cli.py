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

"""
usage: cdns [-h] --host HOST --resolver RESOLVER [--records [RECORDS ...]]
            [--loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}] [--ttl TTL]
            [--max-cache-length MAX_CACHE_LENGTH] [--tls-host TLS_HOST] [--ssl-key SSL_KEY]
            [--ssl-cert SSL_CERT]

A simple forwarding DNS server

options:
  -h, --help            show this help message and exit
  --host HOST, -a HOST  The host address in the format of a.b.c.d:port
  --resolver RESOLVER, -r RESOLVER
                        The resolver address in the format of a.b.c.d:port
  --records [RECORDS ...], -b [RECORDS ...]
                        Path to file containing records
  --loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}, -l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Provide information about the logging level (default = info).
  --ttl TTL, -t TTL     Default TTL for blocked hosts (default = 300)
  --max-cache-length MAX_CACHE_LENGTH, -m MAX_CACHE_LENGTH
                        Maximum length of the cache (default=infinity)
  --tls-host TLS_HOST   TLS socket address in the format of a.b.c.d:port (only needed if using tls)
  --ssl-key SSL_KEY, -sk SSL_KEY
                        Path to SSL key file (only needed if using TLS)
  --ssl-cert SSL_CERT, -sc SSL_CERT
                        Path to SSL cert file (only needed if using TLS)
"""
import argparse
import logging
from .manager import ServerManager
from .zones import Records, load_all_records


def cli() -> None:
    """The command line interface for compactdns."""
    # TODO: Document this more
    parser = argparse.ArgumentParser(
        description="A simple forwarding DNS server", fromfile_prefix_chars="@"
    )
    parser.add_argument(
        "--host",
        "-a",
        required=True,
        type=str,
        help="The host address in the format of a.b.c.d:port",
    )
    parser.add_argument(
        "--resolver",
        "-r",
        required=True,
        type=str,
        help="The resolver address in the format of a.b.c.d:port",
    )
    parser.add_argument(
        "--records",
        "-b",
        # required=False
        type=str,
        help="Path to file containing records",
        nargs="*",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        choices=list(logging.getLevelNamesMapping().keys()),
        default="INFO",
        type=str,
        help="Provide information about the logging level (default = info).",
    )
    parser.add_argument(
        "--ttl",
        "-t",
        default=300,
        type=int,
        help="Default TTL for blocked hosts (default = 300)",
    )
    parser.add_argument(
        "--max-cache-length",
        "-m",
        default=float("inf"),
        type=int,
        help="Maximum length of the cache (default=infinity)",
    )
    parser.add_argument(
        "--tls-host",
        default=None,
        type=str,
        help="TLS socket address in the format of a.b.c.d:port (only needed if using tls)",
    )
    parser.add_argument(
        "--ssl-key",
        "-sk",
        default=None,
        type=str,
        help="Path to SSL key file (only needed if using TLS)",
    )
    parser.add_argument(
        "--ssl-cert",
        "-sc",
        default=None,
        type=str,
        help="Path to SSL cert file (only needed if using TLS)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=args.loglevel.upper(),
        format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    host = args.host.split(":")
    resolver = args.resolver.split(":")
    if args.tls_host is not None:
        tls_host = args.tls_host.split(":")
    else:
        tls_host = None

    if args.records is not None:
        records = load_all_records(args.records, args.ttl)
    else:
        records = Records({}, {})

    logging.debug("Records: %s", records)

    manager = ServerManager(
        host=(host[0], int(host[1])),
        resolver=(resolver[0], int(resolver[1])),
        tls_host=(tls_host[0], int(tls_host[1])) if tls_host is not None else tls_host,
        ssl_key_path=args.ssl_key,
        ssl_cert_path=args.ssl_cert,
        records=records,
        max_cache_length=args.max_cache_length,
    )

    manager.start()
