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
import logging
import sys
import os


from .. import tools
from .. import _installer
from ..manager import ServerManager

from .kwargs import get_kwargs, kwargs_defaults

class LoggerWriter:
    # Needed to write stderr (and stdout) to a file when running in the background
    # Taken from https://stackoverflow.com/a/31688396
    def __init__(self, level):
        # self.level is really like using log.debug(message)
        # at least in my case
        self.level = level

    def write(self, message):
        # if statement reduces the amount of newlines that are
        # printed to the logger
        #if message != '\n':
        message = message.strip()
        if message:
            self.level(message)

    def flush(self):
        # create a flush method so things can be flushed when
        # the system wants to. Not sure if simply 'printing'
        # sys.stderr is the correct way to do it, but it seemed
        # to work properly for me.
        self.level(sys.stderr)


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
    

    install_parser = subparsers.add_parser("install", help="Run the installer (background functionality)")
    install_parser.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Path to configuration file (json or toml)"
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
        kwargs = get_kwargs(args.config, args)

        logger = logging.getLogger()

        # Rather than getLevelNamesMapping, because we can support an older version of python
        logger.setLevel(getattr(logging, kwargs["logging.loglevel"]))

        formatter = logging.Formatter(fmt=kwargs["logging.format"], datefmt=kwargs["logging.datefmt"])

        if kwargs["logging.path"]:
            path = os.path.expanduser(kwargs["logging.path"])
            handler = logging.FileHandler(path)
        else:
            handler = logging.StreamHandler(sys.stdout)
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        # sys.stdout = LoggerWriter(logger.debug)
        # sys.stderr = LoggerWriter(logger.error)

        #logging.basicConfig(
        #    level=logging.getLevelNamesMapping()[kwargs["loglevel"]],
        #    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        #    datefmt="%Y-%m-%d %H:%M:%S",
        #)

        try:
            manager = ServerManager.from_config(kwargs)
            manager.start()
        except Exception as e:
            logging.error("Critical uncaught error (most likely in startup)", exc_info=True)

    elif args.subcommand == "shell":
        host = args.host.split(":")
        tools.shell_client.main(secret=args.secret, addr=(host[0], int(host[1])))
    elif args.subcommand == "h2j":
        tools.h2j.main(args.source, args.dest)

    elif args.subcommand == "install":
        _installer.install(args.config)

