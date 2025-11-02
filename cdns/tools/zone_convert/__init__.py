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


# Entrypoint: Take file, detect format, convert to json
# Detect format: check extension, use regex on body of function

import json
import sys

from publicsuffixlist import PublicSuffixList  # type: ignore
import re
from pathlib import Path
from cdns.zones import FORMAT as FORMAT_
from typing import Literal

FORMAT = Literal[FORMAT_, "host"]


def detect_format(path: Path) -> FORMAT:
    if path.suffix == ".host":
        return "host"
    if path.suffix == ".root":
        return "root"


def convert(src: Path, dest: Path, format: FORMAT | None = None):
    format = detect_format(src)
    if format == "host":
        extractor = PublicSuffixList()

        with open(src) as f:
            lines = f.readlines()

        rules = []
        for line in lines:
            rule = line.strip().split("#")[0].strip().split()
            if rule:
                rules.append(rule)

        dump = {}
        for ip, name in rules:
            root = extractor.privatesuffix(name)

            if root not in dump:
                dump[root] = {}
            if "records" not in dump[root]:
                dump[root]["records"] = {}
            if root == name:  # top level = block all
                dump[root]["records"][root] = {"A": [[ip]]}
                dump[root]["records"]["*." + root] = {"A": [[ip]]}
            else:
                dump[root]["records"][name] = {"A": [[ip]]}

        new = []
        for domain in dump.keys():
            new.append({"domain": domain, **dump[domain]})

        with open(dest, "w") as f:
            json.dump(new, f)

    elif format == "root":
        with open(src) as f:
            lines = f.readlines()

        rule = []
        for line in lines:
            if line[0] == ";":
                continue
