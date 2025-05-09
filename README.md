# CompactDNS (CDNS)
CompactDNS (CDNS) is a minimalistic yet powerful DNS server designed for simplicity and speed, offering local caching and both authoritative and forwarding capabilities.

> In 2025, Google Chrome will remove adblockers with the impending Manifest V3 update. This change threaten the existance of software like UBlock Origin. Rather than abandoning Chrome, I explored alternative ways to block ads. This DNS server, CompactDns, was the result: it's lightweight, blazing fast, and can block ads. It also caches all requests on device, leading to a latency as low as 0 ms.
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

### Running the Server
To start the server:
```bash
cdns run [options]
```
Configuration is stored in a `toml` or `json` file. See `config.toml` for an example configuration.
```bash
cdns run --config onfig.toml
```
The DNS protocol is typically run over port `53` for TCP and `853` for TLS. 

**When TLS is used, a key and certificate file are required.**  
Generate a pair:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Configuration

An example configuration file is available in `config.toml`.

## Running as a Service

### MacOS / OSX

CDNS can be set up to run in the background as a service:

```
sudo cdns install -c /path/to/config
```

This command writes a plist file to `/Library/LaunchDaemons/com.ninjamar.compactdns.plist`. 


Start the server:
```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.ninjamar.compactdns.plist
```
Stop the server:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.ninjamar.compactdns.plist
```
Startup logs are written to `/tmp/cdns-startup.log` and `cdns-startup-err.log` .

**Ensure that all paths in the configuration file are relative to the path of the configuration file.**

### Changing the System DNS Server

CDNS can be configured as the system DNS server. Replace `A.B.C.D` with the address of the server.

On MacOS:
```bash
networksetup -setdnsservers Wi-Fi A.B.C.D
```

## DNS Zones

Zones can be stored in 3 formats:
* Single zone Json file (e.g., `*.json`)
* Multiple zones JSOn file (e.g., `*.all.json`)
* Traditional zone file (e.g., `*.zone`)

See the `example-zones/` directory for examples. 

### From a Host File

To convert a host file to a JSON list:
```bash
cdns tools h2j /path/to/host.txt /path/to/output.all.json
```

**`example-zones/lowe.all.json` was generated from [Peter Lowe's adservers list](https://pgl.yoyo.org/adservers/) using this script**

## Preload Files and Cache Dump

A preload file is a plain text list of hosts to be loaded into the cache before server startup.


```
# These sites will all be preloaded
google.com
github.com
example.com
```

The cache (and also the zones) can be written to a file upon server shutdown and reloaded on startup.

## Architecture

When in recursive mode, the server can achieve latency as low as 0 ms. Initially, cache misses will result in higher latency, but once requests are resolved, responses are cached for the future.
```mermaid
graph TD;
    send["Send the request"]
    done["Response sent back"]
    send --> recv["Server receives the request"]
    recv --> is_cache["Is the request in the cache?"]
    is_cache --> |"Yes"| cache["The request is in the cache"] --> done
    is_cache --> |"No"| recursive["Recursively fulfill the request"]
    recursive --> |"Add response to cache"| done
```

## Other Commands

### `shell`
CDNS includes an interactive debugging shell.

> [!WARNING]
> This feature exists for debbuging. Use at your own risk

> [!NOTE]
> Incoming requests are blocked when in use

Run the shell:
```bash
cdns shell [options]
```

Options:
*  `--host`, `-h`: The host address for the shell server in `a.b.c.d:port` format

The shell opens a Python REPL connected to the main server process.

List the available commands:
```python
>>> help(self.command)
```


## Testing
Some outdated tests exist in `tests/` directory

Instead, send test queries using dig.
```bash
dig @A.B.C.D -p PORT example.com
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.