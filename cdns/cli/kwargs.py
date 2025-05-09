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

import json
import sys

if sys.version_info < (3, 11):
    import tomli as tomllib
else:
    import tomllib

from pathlib import Path

from ..utils import flatten_dict, merge_defaults


class _IFS:
    def __init__(self, **kwargs):
        self.d = kwargs

    def __getitem__(self, x):
        return self.d[x]


# All paths have to be from the root of the config file, so use path=True

# TODO: Merge with above (use tuple) and store type
kwargs_defaults_initial = {
    "logging": {
        "loglevel": _IFS(
            help_="Log level to use. One of {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET'}",
            type_=str,
            default="INFO",
        ),
        "format": _IFS(
            help_="Logging message format",
            type_=str,
            default="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        ),
        "datefmt": _IFS(
            help_="Logging date format", type_=str, default="%Y-%m-%d %H:%M:%S"
        ),
        "log": _IFS(
            help_="Path to log file (leave empty for console)",
            type_=str,
            default=None,
            path=True,
        ),
        "stdout": _IFS(
            help_="Path to stdout/stderr (only needed if running as a service)",
            type_=str,
            default="/tmp/cdns-stdout.log",
            path=True,
        ),
        "stderr": _IFS(
            help_="Path to stdout/stderr (only needed if running as a service)",
            type_=str,
            default="/tmp/cdns-stderr.log",
            path=True,
        ),
    },
    "all": {
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
                help_="Path to SSL key for DNS over TLS",
                type_=str,
                default=None,
                path=True,
            ),
            "ssl_cert": _IFS(
                help_="Path to SSL certificate for DNS over TL",
                type_=str,
                default=None,
                path=True,
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
        "list": _IFS(help_="A list of resolvers to use.", type_=list, default=None),
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
                help_="Domain name for speed test query",
                type_=str,
                default="google.com",
            ),
            "interval": _IFS(help_="Interval between tests", type_=int, default=120),
        }
    },
    "storage": {
        "zone_dirs": _IFS(
            help_="A list of paths to directories containing zones. (*.zone, *.json, *.all.json)",
            type_=list,
            default=None,
            path=True,
        ),
        "zone_path": _IFS(
            help_="Path to a pickled lzma zone", type_=str, default=None, path=True
        ),
        "cache_path": _IFS(
            help_="Path to a pickled lzma cache", type_=str, default=None, path=True
        ),
        "preload_path": _IFS(
            help_="Path to cache preload file", type_=str, default=None, path=True
        ),
    },
}

kwargs_defaults: dict[str, _IFS] = flatten_dict(kwargs_defaults_initial)


def get_kwargs(config_path, args=None) -> dict[str, str | int | bool]:
    """Normalize/process kwargs from a path.

    Args:
        config_path: Path to config.
        args: Args to program. Defaults to None.

    Raises:
        ValueError: Unknown configuration file format.

    Returns:
        The processed kwargs.
    """
    kwargs = {}

    if config_path is not None:
        if config_path.endswith(".json"):
            with open(config_path) as f:
                kwargs.update(json.load(f))
        elif config_path.endswith(".toml"):
            with open(config_path, "rb") as f:
                kwargs.update(tomllib.load(f))
        else:
            raise ValueError("Unable to load configuration: unknown file format")

    if args:
        kwargs.update(
            {k: v for k, v in vars(args).items() if v is not None and k != "subcommand"}
        )

    kwargs = merge_defaults(
        {k: v["default"] for k, v in kwargs_defaults.items()},
        flatten_dict(kwargs),
    )

    base_path = Path(config_path).parent
    paths = [k for k, v in kwargs_defaults.items() if v.d.get("path") is not None]
    for path in paths:
        if kwargs[path] is not None:
            if kwargs_defaults[path]["type_"] == list:
                #  for x in path]
                kwargs[path] = [(base_path / Path(x)).resolve() for x in kwargs[path]]
            else:
                kwargs[path] = (base_path / Path(kwargs[path])).resolve()

    return kwargs
