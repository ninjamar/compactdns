# CompactDNS (CDNS)
A simple forwarding DNS server with the ability to block certain websites.

> [!WARNING]
> CDNS probably doesn't conform exactly to the [DNS specification](https://www.rfc-editor.org/rfc/rfc1035)

## Installation

Download this repository (or `cdns.py`). This project only depends on the Python standard library.


## Usage
```
usage: cdns.py [-h] --host HOST --resolver RESOLVER [--blocklist [BLOCKLIST ...]]
               [--loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
               [--mode {normal,threaded}] [--ttl TTL]

A simple forwarding DNS server

options:
  -h, --help            show this help message and exit
  --host HOST, -a HOST  The host address in the format of a.b.c.d:port
  --resolver RESOLVER, -r RESOLVER
                        The resolver address in the format of a.b.c.d:port
  --blocklist [BLOCKLIST ...], -b [BLOCKLIST ...]
                        Path to file containing blocklist
  --loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}, -l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Provide information about the logging level (default = info)
  --mode {normal,threaded}, -m {normal,threaded}
                        Mode to run server (default = threaded)
  --ttl TTL             Default TTL for blocked hosts
```

or since `fromfile_prefix_chars="@"`, store the arguments inside a file (eg `./config.txt`).
```
python cdns.py @config.txt
```
### Example
```
python cdns.py --host 127.0.0.1 --resolver 1.1.1.1:53 --blocklist example-blocklists/blocklist.toml --loglevel INFO --mode threaded --ttl 60
```
Runs the DNS server on `127.0.0.1:2053`, forwarding queries to `1.1.1.1:53`. For blocked sites, returns to `127.0.0.2`. Server is run in threaded mode and log level INFO.

### Blocklist Format
Blocklists should be either a `toml` or `json` file. See `blocklist.toml` and `blocklist.json` for an example.

The file contains a list of rules (`rules`), which have a list of hosts (`hosts`)that get blocked to a certain ip address (`block_ip`). Key value pairs of host to ip address can be specified in the `blocklist` section.

Multiple blocklists can be given as an input.
### Loopback Addresses

DNS servers run on port 53. If you want to run this on port 53, run this as root.

If you don't want to clog up the loopback address, make a new one.
#### MacOS
```
sudo ifconfig lo0 alias 127.X.X.X up
```
### Linux (unverified)
```
sudo ip addr add 127.X.X.X/8 dev lo
```
Make sure the new loopback address is in the correct range.

### Set DNS servers
#### MacOS
```
networksetup -setdnsservers Wi-Fi 127.X.X.X
```
### Testing
#### DNS Server is being used on port 53 and by the computer
```
dig some.url
```
#### Otherwise
```
dig @127.X.X.X -p X some.url
```
