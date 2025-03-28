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

# TODO: Show usage notice

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

class _IFS:
    def __init__(self, **kwargs):
        self.d = kwargs
    def __getitem__(self, x):
        return self.d[x]

# TODO: Merge with above (use tuple) and store type
kwargs_defaults = {
    "loglevel": _IFS(
        help_="Log level to use. One of {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET'}",
        type_=str,
        default="INFO",
    ),
    "all": {
        "fallback_ttl": _IFS(
            help_="Fallback TTL for all requests", type_=int, default=300
        ),
        "ttl_min": _IFS(
            help_="TTL minimum for storage and resolver", type_=int, default=200
        ),
        "max_workers": _IFS(
            help_="Max number of workers for the DNS server", type_=int, default=50
        ),
    },
    "servers": {
        "host": {
            "host": _IFS(
                help_="Address of the host (a.b.c.d)", type_=str, default="127.0.0.1"
            ),
            "port": _IFS(help_="Port of server", type_=int, default=2053),
        },
        "tls": {
            "host": _IFS(
                help_="Host of DNS over TLS host (a.b.c.d)", type_=str, default=None
            ),
            "port": _IFS(help_="Port of DNS over TLS", type_=int, default=2853),
            "ssl_key": _IFS(
                help_="Path to SSL key for DNS over TLS", type_=str, default=None
            ),
            "ssl_cert": _IFS(
                help_="Path to SSL certificate for DNS over TL", type_=str, default=None
            ),
        },
        # TODO: Make shell optional
        "debug_shell": {
            "host": _IFS(
                help_="Address of shell server (a.b.c.d)", type_=str, default=None
            ),
            "port": _IFS(help_="Port of shell server", type_=int, default=2053),
        },
    },
    "resolver": {
        "recursive": _IFS(help_="Is the resolver recursive?", type_=bool, default=True),
        "list": _IFS(
            help_="A list of resolvers to use.", type_=list, default=None
        ),
        "add_system": _IFS(
            help_="Add the system resolvers to the resolvers", type_=bool, default=False
        ),
    },
    "daemons": {
        "fastest_resolver": {
            "use": _IFS(
                help_="Should the fastest resolver daemon be used?",
                type_=bool,
                default=False,
            ),
            "test_name": _IFS(
                help_="Domain name for speed test query", type_=str, default="google.com"
            ),
            "interval": _IFS(help_="Interval between tests", type_=int, default=120),
        }
    },
    "storage": {
        "zone_dirs": _IFS(
            help_="A list of paths to directories containing zones. (*.zone, *.json, *.all.json)",
            type_=list,
            default=None,
        ),
        "zone_path": _IFS(help_="Path to a pickled lzma zone", type_=str, default=None),
        "cache_path": _IFS(
            help_="Path to a pickled lzma cache", type_=str, default=None
        ),
        "preload_path": _IFS(
            help_="Path to cache preload file", type_=str, default=None
        ),
    },
}

kwargs_defaults = flatten_dict(kwargs_defaults)


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
    
    for key, value in kwargs_defaults.items():
        # HACK-TYPING: I don't know how to get mypy to not complain here
        parser_run.add_argument(
            f"--{key}",
            help=value["help_"],
            type=value["type_"] if value["type_"] != list else None,
            nargs="+" if value["type_"] == list else None,  # type: ignore[arg-type]
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
        # if len(kwargs.keys()) == 0:
        #    parser_run.print_help()
        #    sys.exit(1)

        kwargs = merge_defaults(
            {k: v["default"] for k, v in kwargs_defaults.items()},
            flatten_dict(kwargs),
        )
        # kwargs = merge_defaults(kwargs_defaults, kwargs)
        # kwargs = flatten_dict(kwargs)
        logging.basicConfig(
            level=logging.getLevelNamesMapping()[kwargs["loglevel"]],
            format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        manager = ServerManager.from_config(kwargs)
        manager.start()

    elif args.subcommand == "shell":
        host = args.host.split(":")
        tools.shell_client.main(secret=args.secret, addr=(host[0], int(host[1])))
    elif args.subcommand == "h2j":
        tools.h2j.main(args.source, args.dest)
