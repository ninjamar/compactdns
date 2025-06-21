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

import textwrap
import shutil
import pwd
import grp
import os
import importlib.resources as ir
import os.path
import sys
from pathlib import Path

from cdns.cli.kwargs import get_kwargs
from cdns.utils import colors


def get_cdns_path() -> str:
    """Get the path to the cdns executable.

    Returns:
        The path to the cdns executable.
    """
    return os.path.abspath(sys.argv[0])

class Installer:
    def __init__(self, config_path, kwargs):
        with ir.open_text("cdns._installer.data", "com.ninjamar.compactdns.plist") as f:
            self.MAIN_TEMPLATE = f.read()
        with ir.open_text("cdns._installer.data", "com.ninjamar.sleepwatcher-root-cdns.plist") as f:
            self.WATCH_TEMPLATE = f.read()

        self.main_install_path = "/Library/LaunchDaemons/com.ninjamar.compactdns.plist"
        self.watch_install_path = "/Library/LaunchDaemons/com.ninjamar.cdns-sleepwatcher-root.plist"


        self.watch_root_all_path = ir.files("cdns._installer.data") / "sleepwatcher-root.sh"
        self.watch_shell_path = ir.files("cdns._installer.data") / "macos_watcher.sh"

        self.cdns_path = get_cdns_path()

        self.kwargs = kwargs
        self.config_path = config_path


    def generate_main_plist(self) -> str:
        if not self.kwargs["logging.stdout"] or not self.kwargs["logging.stderr"]:
            raise Exception("Need stdout/stderr paths")
        
        return self.MAIN_TEMPLATE.format(
            cdns_path=self.cdns_path,
            config_path=Path(self.config_path).resolve(),
            stdout_path=Path(self.kwargs["logging.stdout"]).resolve(),
            stderr_path=Path(self.kwargs["logging.stderr"]).resolve(),
        )

    def generate_watch_plist(self, sleepwatcher_path):
        return self.WATCH_TEMPLATE.format(
            sleepwatcher_path=sleepwatcher_path,
            wakeup_path="/etc/cdns/sleepwatcher-root.sh"
        )

    def install(self):
        print(textwrap.dedent(f"""
            CDNS has two components to install:
                - The server daemon/background process (MAIN)
                - A daemon to restart the server (WATCH)
              
            {colors.WARNING}WATCH requires sleepwatcher to be installed:{colors.ENDC}
                brew install sleepwatcher

            If sleepwatcher is installed, this installer will continue. If it isn't (or cannot be found in PATH),
            then this installer will quit. Re-run the installer when sleepwatcher has been installed.
        
        """))
        sleepwatcher_path = shutil.which("sleepwatcher")
        if sleepwatcher_path is None:
            print(f"{colors.FAIL}Sleepwatcher cannot be found. Exiting.{colors.ENDC}")
            return
        
        with open(self.main_install_path, "w") as f:
            f.write(self.generate_main_plist())

        os.makedirs("/etc/cdns/sleepwatcher-root.d/", exist_ok=True)

        if os.path.lexists("/etc/cdns/sleepwatcher-root.d/watch.sh"):
            os.remove("/etc/cdns/sleepwatcher-root.d/watch.sh")
        os.symlink(self.watch_shell_path, "/etc/cdns/sleepwatcher-root.d/watch.sh")

        if os.path.lexists("/etc/cdns/sleepwatcher-root.sh"):
            os.remove("/etc/cdns/sleepwatcher-root.sh")
        os.symlink(self.watch_root_all_path, "/etc/cdns/sleepwatcher-root.sh")

        # Make sure root owns this path

        # sudo chown root:wheel /etc/cdns/sleepwatcher-root.sh
        # sudo chmod 755 /etc/cdns/sleepwatcher-root.sh

        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam("wheel").gr_gid

        os.chown("/etc/cdns/sleepwatcher-root.sh", uid, gid)
        os.chmod("/etc/cdns/sleepwatcher-root.sh", 0o755) # Just means 755 permission

        with open(self.watch_install_path, "w") as f:
            f.write(self.generate_watch_plist(sleepwatcher_path))
        
        print(textwrap.dedent(f"""
            MAIN has been written to {self.main_install_path}
            WATCH has been written to {self.watch_install_path}

            To start both now:
                sudo launchctl bootstrap system {self.main_install_path}
                sudo launchctl bootstrap system {self.watch_install_path}

            To stop both:
                sudo launchctl bootout system {self.main_install_path}
                sudo launchctl bootout system {self.watch_install_path}
        """))


def main(config_path) -> None:
    """Generate and write a plist file.

    Args:
        config_path: Path to configuration.
        out_path: Path to write plist file to.
    """
    # TODO: Assert config path exists
    kwargs = get_kwargs(config_path)
    
    i = Installer(config_path, kwargs)
    i.install()