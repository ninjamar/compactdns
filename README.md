# CompactDNS (CDNS)
A simple forwarding DNS server with the ability to block certain websites.

> [!WARNING]
> CDNS probably doesn't conform exactly to the [DNS specification](https://www.rfc-editor.org/rfc/rfc1035)

## Installation

Download this repository (or `cdns.py`). This project only depends on the Python standard library.


## Usage
```
usage: cdns.py [-h] --host HOST --resolver RESOLVER --redirect REDIRECT [--blocklist BLOCKLIST]
               [--loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}] [--mode {normal,threaded}]
               [--ttl TTL]

A simple forwarding DNS server

options:
  -h, --help            show this help message and exit
  --host HOST, -a HOST  The host address in the format of a.b.c.d:port
  --resolver RESOLVER, -r RESOLVER
                        The resolver address in the format of a.b.c.d:port
  --redirect REDIRECT, -R REDIRECT
                        The IP address to redirect to in the format of a.b.c.d
  --blocklist BLOCKLIST, -b BLOCKLIST
                        Path tofile containing blocklist (fnmatch syntax)
  --loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}, -l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Provide information about the logging level (default = info)
  --mode {normal,threaded}, -m {normal,threaded}
                        Mode to run server (default = threaded)
  --ttl TTL             Default TTL for blocked hosts
```
### Example
```
python cdns.py --host 127.0.0.1:2053 --resolver 1.1.1.1:53 --redirect 127.0.0.2
```
Runs the DNS server on `127.0.0.1:2053`, forwarding queries to `1.1.1.1:53`. For blocked sites, returns to `127.0.0.2`. Server is run in threaded mode and log level INFO.

### Loopback Addresses

DNS servers run on port 53. If you want to run this on port 53, use sudo.

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
