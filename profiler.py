import statistics
import sys
import time

from cdns import *


def humanize_float(n):
    if n == 0:
        return 0
    abs_n = abs(n)

    if abs_n < 1e-9:
        return f"{n * 1e12:.3f} ps"  # Picoseconds
    elif abs_n < 1e-6:
        return f"{n * 1e9:.3f} ns"  # Nanoseconds
    elif abs_n < 1e-3:
        return f"{n * 1e6:.3f} µs"  # Microseconds
    elif abs_n < 1:
        return f"{n * 1e3:.3f} ms"  # Milliseconds
    else:
        raise Exception("Unable to format")


def time_fn(fn, *args, **kwargs):
    start = time.time()
    fn(*args, **kwargs)
    elapsed = time.time() - start
    return elapsed


def main(n_times):
    # This is what the server decodes when using dig
    # $ dig @127.0.0.1 -p 2053 google.com
    query = pack_all_compressed(
        DNSHeader(
            id_=62967,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=2,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=1,
        ),
        [DNSQuestion(decoded_name="google.com", type_=1, class_=1)],
    )
    manager = ServerManager(
        host=("127.0.0.1", 2053),  # Not needed
        resolver=("1.1.1.1", 53),  # Needed
        blocklist={},  # Right now, isn't needed, but may change
    )

    results = []
    for i in range(n_times):
        results.append(time_fn(manager.handle_dns_query, query))

    mean = statistics.fmean(results)

    # Only mean
    if "-f" in sys.argv:
        print(humanize_float(mean))
    else:
        print(f"Ran {n_times} iterations, Average Time: {humanize_float(mean)}")


if __name__ == "__main__":
    main(int(sys.argv[1]))
