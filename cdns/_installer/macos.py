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

import os.path
import sys
from pathlib import Path

from ..cli.kwargs import get_kwargs

# Need to have exact binary path
# /tmp/cdns-startup.log and /tmp/cdns-startup-err.log are use for logging
# during startup, before the main logger is configured.

TEMPLATE = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ninjamar.compactdns</string>
    <key>ProgramArguments</key>
    <array>
        <string>{cdns_path}</string>
        <string>run</string>
        <string>-c</string>
        <string>{config_path}</string>
    </array>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>3</integer>

    <key>StandardOutPath</key>
    <string>{stdout_path}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_path}</string>
</dict>
</plist>
"""


def get_cdns_path() -> str:
    """Get the path to the cdns executable.

    Returns:
        The path to the cdns executable.
    """
    return sys.argv[0]


def generate_plist(config_path) -> str:
    """Generate a plist file corresponding to a specific configuration path.

    Args:
        config_path: Path to config file.

    Returns:
        The plist file contents.
    """
    kwargs = get_kwargs(config_path)
    return TEMPLATE.format(
        cdns_path=get_cdns_path(),
        config_path=Path(config_path).resolve(),
        stdout_path=Path(kwargs["logging.stdout"]).resolve(),
        stderr_path=Path(kwargs["logging.stderr"]).resolve(),
    )


def main(config_path, out_path) -> None:
    """Generate and write a plist file.

    Args:
        config_path: Path to configuration.
        out_path: Path to write plist file to.
    """
    out_path = os.path.expanduser(out_path)
    data = generate_plist(config_path)
    with open(out_path, "w") as f:
        f.write(data)

    print(f"Wrote plist to {out_path}")
    print("This program has been configured to run at boot.")
    print("Run the following to start the program immediately")
    print(f"sudo launchctl bootstrap system {out_path}")
    print("To stop it, run")
    print(f"sudo launchctl bootout system {out_path}")
