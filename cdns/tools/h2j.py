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
"""Hosts to JSON blocklist.

Usage: cdns tools h2j path/to/host path/to/target.all.json
"""

import json
import sys

from publicsuffixlist import PublicSuffixList  # type: ignore

extractor = PublicSuffixList()


def main(host, target):
    with open(host) as f:
        rules = f.readlines()

    rules = [v for rule in rules if (v := rule.strip().split("#")[0].strip().split())]

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

    with open(target, "w") as f:
        json.dump(new, f)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
