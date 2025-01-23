# DNS-Server

Simple forwarding DNS server written in Python


## Example

```bash
python3 main.py --host localhost:2053 --resolver 1.1.1.1:53
```

**Testing**
```bash
 dig @127.0.0.1 -p 2053 google.com

```