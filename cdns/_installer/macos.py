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

import sys
import os.path
from pathlib import Path
from cdns.cli.kwargs import get_kwargs

# TODO: Open template from file
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
    <true/>

    <key>Sockets</key>
    <dict>
        {sockets}
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{PATH}</string>
    </dict>
</dict>
</plist>
"""

SOCKET_TEMPLATE = """
<key>{name}</key>
<dict>
    <key>SockServiceName</key>
    <string>{service}</string>
    <key>SockType</key>
    <string>{type}</string>
    <key>SockFamily</key>
    <string>{family}</string>
</dict>
"""

def get_cdns_path():
    return sys.argv[0]
    # return subprocess.check_output(["which", "cdns"]).decode().strip()

def generate_plist_from_config_dict(config, config_path):
    sockets = []

    udp = config["servers.host.host"]
    udp_port = config["servers.host.port"]
    tcp = config["servers.host.host"]
    tcp_port = config["servers.host.port"]
    tls = config["servers.tls.host"]
    tls_port = config["servers.tls.port"]
    debug_shell = config["servers.debug_shell.host"]
    debug_shell_port = config["servers.debug_shell.port"]

    if udp and udp_port:
        sockets.append(SOCKET_TEMPLATE.format(name="UDP", service="domain" if udp_port == 53 else udp_port, type="dgram", family="IPv4"))
    if tcp and tcp_port:
        sockets.append(SOCKET_TEMPLATE.format(name="TCP", service="domain" if tcp_port == 53 else tcp_port, type="stream", family="IPv4"))
    
    if tls and tls_port:
        sockets.append(SOCKET_TEMPLATE.format(name="TLS", service="domain-s" if tls_port == 853 else tls_port, type="stream", family="IPv4"))

    if debug_shell and debug_shell_port:
        sockets.append(SOCKET_TEMPLATE.format(name="DEBUG", service=debug_shell_port, type="dgram", family="IPv4"))

    # print(Path(config_path).resolve())
    return TEMPLATE.format(cdns_path=get_cdns_path(), sockets="\n".join(sockets), config_path=Path(config_path).resolve(), PATH=os.environ["PATH"])

def main(config_path, out_path):
    out_path = os.path.expanduser(out_path)
    config = get_kwargs(config_path, _no_args=True)
    data = generate_plist_from_config_dict(config, config_path)
    with open(out_path, "w") as f:
        f.write(data)

    print(f"Wrote plist to {out_path}")
        