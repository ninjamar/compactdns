# CompactDNS (CDNS)
CompactDNS, also known as CDNS is a authoritative and forwarding DNS server.

## Features
- Easy to setup
- Can be configured as an adblocker
- Caches responses locally


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

### Commands

#### `run`
Starts the DNS server.
```bash
cdns run [options]
```
Configuration is stored in a `toml` or `json` file. See `config.toml` for an example configuration.
```bash
cdns run --config config.toml
```


#### `shell`
```bash
cdns shell [options]
```

Options:
  `--host`, `-h`: The host address of the shell server in the format of a.b.c.d:port
  `--secret`, `s`: The secret of the shell server. The secret is logged when cdns is started.

### TLS

A key and certificate file is needed to use TLS.
Generate it:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### Interactive shell

For debugging, CDNS includes an interactive python shell. The shell can be accessed using the `shell` command.
```bash
>>> help(self.command)
>>> help(cdns.manager.ServerManager.command)
```

## DNS Zones

DNS zones can be stored in a folder. Make sure that each filename is in the format of `domain.zone`.

## Changing the DNS server

On MacOS:
```bash
networksetup -setdnsservers Wi-Fi A.B.C.D
```

DNS runs over port `53` for both UDP and TCP.

## Testing

Send test queries using dig.
```bash
dig @A.B.C.D -p PORT google.com
```

## License

This project is licensed under the MIT License. Please see the LICENSE file for more details.