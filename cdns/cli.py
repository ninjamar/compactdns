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
import json
import logging
import sys

if sys.version_info < (3, 11):
    import tomli as tomllib
else:
    import tomllib

from . import tools
from .manager import ServerManager
from .utils import flatten_dict, merge_defaults

kwargs_defaults = {
    "max_workers": 50,
    "loglevel": "INFO",
    "servers": {
        "host": {"host": "127.0.0.1", "port": 2053},
        "tls": {
            "host": None,
            "port": None,
            "ssl_key": None,
            "ssl_cert": None,
        },
        "shell": {"host": "127.0.0.1", "port": 2055},
    },
    "resolver": {
        "resolvers": [],
        "use_fastest": True,
        "add_system": True,
        "interval": 120,
    },
    "storage": {
        "zone_dirs": [],
        "zone_pickle_path": None,
        "cache_pickle_path": None,
    },
    "daemons": {
        "fastest_resolver": {"use": False, "test_name": "github.com", "interval": 100}
    },
}
kwargs_defaults_help = {
    "max_workers": "Max number of workers for the DNS server",
    "loglevel": "Log level to use. One of {{CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET'}}",
    "servers": {
        "host": {"host": "Address of the host (a.b.c.d)", "port": "Port of server"},
        "tls": {
            "host": "Host of DNS over TLS host (a.b.c.d)",
            "port": "Port of DNS over TLS",
            "ssl_key": "Path to SSL key for DNS over TLS",
            "ssl_cert": "Path to SSL certificate for DNS over TL",
        },
        "shell": {
            "host": "Address of shell server (a.b.c.d)",
            "port": "Port of shell server",
        },
    },
    "resolver": {
        "resolvers": "A list of resolvers to use.",
        "use_fastest": "Should the fastest resolver be used?",
        "add_system": "Add the system resolvers to the resolvers",
        "interval": "How often should the fastest resolver be updated?",
    },
    "storage": {
        "zone_dirs": "A list of paths to directories containing zones. (*.zone, *.json, *.all.json)",
        "zone_pickle_path": "Path to a pickled zone",
        "cache_pickle_path": "Path to a pickled cache",
    },
}


def cli() -> None:
    """The command line interface for compactdns."""
    # TODO: Document this more
    parser = argparse.ArgumentParser(
        description="A simple forwarding DNS server", fromfile_prefix_chars="@"
    )
    subparsers = parser.add_subparsers(help="Functions", dest="subcommand")

    tools_parser = subparsers.add_parser("tools", help="Run a tool")
    tools_subparser = tools_parser.add_subparsers(
        help="Tools", dest="subcommand", required=True
    )

    h2j_parser = tools_subparser.add_parser(
        "h2j", help="Convert a host file to a json zone."
    )
    h2j_parser.add_argument("source", help="Source of host file (/etc/hosts)")
    h2j_parser.add_argument("dest", help="Destination file (.all.json)")

    parser_shell = tools_subparser.add_parser(
        "shell", help="Open the interactive shell"
    )
    parser_shell.add_argument("--secret", "-s", default=None, help="Shell secret")
    parser_shell.add_argument("--host", "-a", required=True, help="Host of server")

    parser_run = subparsers.add_parser("run", help="Run the DNS server")
    parser_run.add_argument(
        "--config",
        "-c",
        type=str,
        help="Path to configuration file (json or toml)",
    )

    for (key, value), msg in zip(
        flatten_dict(kwargs_defaults).items(),
        flatten_dict(kwargs_defaults_help).values(),
    ):

        # HACK-TYPING: I don't know how to get mypy to not complain here
        parser_run.add_argument(
            f"--{key}",
            help=msg,
            type=(
                str  # type: ignore[arg-type]
                if isinstance(value, str)
                else (int if isinstance(value, int) else None)
            ),
            nargs="+" if isinstance(value, list) else None,  # type: ignore[arg-type]
        )

    # TODO: Help message for kwargs

    args, unknown = parser.parse_known_args()

    if args.subcommand is None:
        parser.print_help()
        sys.exit(1)

    elif args.subcommand == "run":
        kwargs = {}
        # TODO: Parse using argparse
        # if len(unknown) > 0:
        #    parser = argparse.ArgumentParser()

        # kwargs.update(dict(zip(unknown[:-1:2], unknown[1::2])))
        if args.config is not None:
            if args.config.endswith(".json"):
                with open(args.config) as f:
                    kwargs.update(json.load(f))
            elif args.config.endswith(".toml"):
                with open(args.config, "rb") as f:
                    kwargs.update(tomllib.load(f))
            else:
                raise ValueError("Unable to load configuration: unknown file format")

        # kwargs.update(vars(args))
        kwargs.update(
            {k: v for k, v in vars(args).items() if v is not None and k != "subcommand"}
        )
        if len(kwargs.keys()) == 0:
            parser_run.print_help()
            sys.exit(1)

        kwargs = merge_defaults(kwargs_defaults, kwargs)
        kwargs = flatten_dict(kwargs)

        logging.basicConfig(
            level=logging.getLevelNamesMapping()[kwargs["loglevel"]],
            format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        manager = ServerManager.from_config(kwargs)
        manager.start()

    elif args.subcommand == "shell":
        host = args.host.split(":")
        print(args.secret)
        tools.shell_client.main(secret=args.secret, addr=(host[0], int(host[1])))
    elif args.subcommand == "h2j":
        tools.h2j.main(args.source, args.dest)
