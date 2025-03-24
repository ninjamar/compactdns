"""
import socket
from cdns.protocol import DNSHeader, DNSQuestion, DNSAuthority, DNSAdditional, pack_all_compressed, unpack_all

addr = ("198.41.0.4", 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

buf = pack_all_compressed(
    DNSHeader(id_=100, qdcount=1), [DNSQuestion(decoded_name="google.com")]
)

sock.sendto(buf, addr)

resp, addr = sock.recvfrom(512)
# print(resp)

h, q, a = unpack_all(resp)
locs = zip([a for a in a if isinstance(a, DNSAuthority)], [a for a in a if isinstance(a, DNSAdditional)])
print(list(locs)[0])

# print(h, q, a)

sock.close()
"""
import time
from cdns.resolver import RecursiveResolver
from cdns.protocol import DNSQuery, DNSHeader, DNSQuestion, DNSQuery

r = RecursiveResolver()

q = DNSQuery(DNSHeader(qdcount=1), [DNSQuestion(decoded_name="fewfwefwefwefwefwefwe.io")]).pack()

now = time.time()
f = r.send(q)
def done(f):
    d = f.result()
    print(d)
    print("Elapsed", time.time() - now)
    # print(unpack_all(d))
f.add_done_callback(done)
f.result()
"""
u = UdpForwarder()
f = u.forward(q, ("198.41.0.4", 53))
f.add_done_callback(lambda f: print("Done"))

res = f.result()
"""