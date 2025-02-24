# TODO

## Protocol

- [x] Support DNS over TLS - https://datatracker.ietf.org/doc/html/rfc7858
- [ ] Support DNS over HTTPS (DOH) - https://datatracker.ietf.org/doc/html/rfc8484
- [ ] Look at https://datatracker.ietf.org/doc/html/rfc8310
- [ ] Review DNS specification RFC1035
- [ ] Support if TC in header, than packet is longer than 512 bytes
- [ ] Remember to set appropriate flags
- [ ] Support multiple packets for a single request
- [ ] When request times out, kill connection
- [ ] Support multiple questions stored in database



### Useful Protocol Stuff

- [ ] Support zone files
- [ ] Choose fastest DNS resolver
- [ ] Implement zones stuff etc
- [ ] Support IPV6
- [ ] Look at NAPTR
- [ ] Option for forwarding dns server or a recursive dns server
    - Ask root server for tld resolver
    - Then ask tld resolver for name server
    - Ask name server for host

### CLI
- [ ] Support -b FILE FILE FILE and -b FILE -b FILE -b FILE
- [ ] Configuration file format other than fromfile_prefix_chars
- [ ] Verbose mode (better logging stuff)



### Speed
- [x] Benchmark via profiler.py
- [ ] Forward logging to logging process (via multiprocessing) (look at logging, because this might be default)
- [x] Max size on TimedCache
- [ ] Add more information about speed, since this can avoid additional network overhead.
- [ ] Add timeout to ThreadPoolExecutor
- [ ] Make sure the threading part of the server is working
- [ ] Async programming for speed
- [x] Remove bottleneck when forwarding dns query




### Other
- [ ] LocalRecords vs Blocklist etc
- [ ] Allow setup as docker container
- [ ] implement str and repr for DNSHeader, DNSQuestion, and DNSAnswer
- [ ] Write TimedCache to file on interval. Also command to purge this file.
- [ ] Allow multiple IP addresses in blocklist


### Organization
- [ ] Document the archictecture (comments)
- [ ] Ensure all code is right (via tests)
- [ ] Document this code more
- [ ] Document and organize `handle_dns_query`
- [ ] Turn this into a module in a directory
- [ ] When this is a module, maybe allow some DNS tunneling and messaging stuff?
- [ ] Add contributing guide to README before 1.0.0
- [ ] Once version 1.0.0 is released, upload this project to PyPi
- [ ] Update readme