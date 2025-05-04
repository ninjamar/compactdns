# CompactDNS (CDNS)
CompactDNS (CDNS) is a privacy-oriented and bloat-free recursive DNS server.

> In 2025, Google Chrome will remove adblockers with the impending manifest V3 update. This horrific change will threaten the existance of software such as UBlock Origin. Instead of ditching Chrome, I decided to see how I could block ads. This DNS server, CompactDns, solves exactly that: it's lightweight, blazing fast, and can block ads. Oh, and did I mention is caches requests on device, leading to an average latency time of only 1 ms..
> 
> \- ninjamar

## Installation

Install CDNS from source
```bash
git clone https://github.com/ninjamar/compactdns
cd compactdns
pip install .
```
For development,
```bash
pip install -e .
```

## Usage

After installation, CDNS can be used by running:
```bash
cdns [command] [options]
```

The server can be run as a daemon, or as a standalone program. 



### Running the server
To start the server:
```bash
cdns run [options]
```
Configuration is stored in a `toml` or `json` file. See `config.toml` for an example configuration.
```bash
cdns run --config onfig.toml
```
The DNS protocol is typically run over port `53` for TCP and `853` for TLS. 

**When TLS is used, a key and certificate file are needed.**  
Generate a pair:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Configuration

An example configuration file can be found in `config.toml`.

## Running as a service

### MacOS / OSX

CDNS can be setup to run in the background / as a service.

```
$ sudo cdns install -c /path/to/config
```

This will write a plist file to `/Library/LaunchDaemons/com.ninjamar.compactdns.plist`. 

To start the server, run `sudo launchctl bootstrap system /Library/LaunchDaemons/com.ninjamar.compactdns.plist`.

To stop the server, run `sudo launchctl bootout system /Library/LaunchDaemons/com.ninjamar.compactdns.plist`

Log files before program initialization will be written to `/tmp/cdns-startup.log` and `cdns-startup-err.log` .

**Make sure that all paths in the configuration file are relative to the path of the configuration file.**

### Changing the DNS server

CDNS can be configured as the system DNS server.

Replace `A.B.C.D` with the address of the server.

On MacOS:
```bash
networksetup -setdnsservers Wi-Fi A.B.C.D
```

## DNS Zones

Zones can be stored in 3 formats: a JSON file containing a singular zone (ends with `.json`), a JSON file containing many zones (ends with `.all.json`), or a proper zone file. (ends with `.zone`)

See `example-zones/` for examples. 

### From a host file

To convert a host file to a json list:
```bash
cdns tools h2j /path/to/host.txt /path/to/output.all.json
```

**`example-zones/lowe.all.json` was generated from [Peter Lowe's adservers list](https://pgl.yoyo.org/adservers/) using this script**


## Other commands

### `shell`
CDNS has an interactive debugging shell.

> [!WARNING]
> This feature exists for debbuging. 
> Use at your own risk

**Requests are blocked when in use**
```bash
cdns shell [options]
```

Options:
  `--host`, `-h`: The host address of the shell server in the format of `a.b.c.d:port`

The shell will open a Python REPL hooked up to the main server process.

See the available commands:
```bash
>>> help(self.command)
```


## Testing
There are some tests in `/tests` but those are quite outdated.

Instead, send test queries using dig.
```bash
dig @A.B.C.D -p PORT example.com
```

## License

This project is licensed under the MIT License. Please see the LICENSE file for more details.