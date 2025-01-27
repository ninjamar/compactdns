# DNS-Server

Simple forwarding DNS server written in Python


## Example

Create a new loopback interface
`sudo ifconfig lo0 alias 127.0.0.2 up`
Set DNS (MAc)
`networksetup -setdnsservers Wi-Fi 127.0.0.1`

```bash
python3 main.py --host localhost:2053 --resolver 1.1.1.1:53
```

**Testing**
```bash
 dig @127.0.0.1 -p 2053 google.com

```