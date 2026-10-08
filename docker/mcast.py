#!/usr/bin/env python3
"""Broadcast/multicast test tool for docker/multicast-test.sh (§9.5.1).

  mcast.py listen PORT OUT [--group G --iface IP] [--pong]
      Count datagrams on PORT into OUT ("<count> <sources...>"), every
      0.2 s. --pong answers each with a unicast "pong".
  mcast.py send DST PORT SRC COUNT RATE [--wait S]
      Send COUNT datagrams at RATE per second from SRC (an ephemeral
      port), out of SRC's interface; then count unicast replies for S
      seconds and print "sent=N replies=M from=a,b".
"""
import os
import socket
import sys
import time


def opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        return args[i + 1]
    return default


def listen(args):
    port, out = int(args[0]), args[1]
    group, iface = opt(args, "--group"), opt(args, "--iface")
    pong = "--pong" in args
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Broadcasts arrive for the wildcard address only.
    s.bind(("0.0.0.0", port))  # noqa: S104
    if group and iface:
        mreq = socket.inet_aton(group) + socket.inet_aton(iface)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.settimeout(0.2)
    count, sources, last = 0, set(), 0.0
    while True:
        try:
            data, addr = s.recvfrom(65535)
            count += 1
            sources.add(addr[0])
            if pong:
                s.sendto(b"pong", addr)
        except TimeoutError:
            pass
        now = time.time()
        if now - last >= 0.2:
            last = now
            with open(out + ".tmp", "w") as f:
                f.write(f"{count} {' '.join(sorted(sources))}\n")
            os.replace(out + ".tmp", out)


def send(args):
    dst, port, src = args[0], int(args[1]), args[2]
    count, rate = int(args[3]), float(args[4])
    wait = float(opt(args, "--wait", "2"))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    # Linux loops broadcasts back to the sending host too; not wanted here.
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    # Bound to the overlay address: Linux sends a limited broadcast out of
    # the interface that holds the source address.
    s.bind((src, 0))
    gap = 1.0 / rate
    start = time.time()
    for i in range(count):
        s.sendto(b"ping %d %f" % (i, time.time()), (dst, port))
        delay = start + (i + 1) * gap - time.time()
        if delay > 0:
            time.sleep(delay)
    s.settimeout(0.2)
    replies, sources = 0, set()
    end = time.time() + wait
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
            if data == b"pong":
                replies += 1
                sources.add(addr[0])
        except TimeoutError:
            pass
    print(f"sent={count} replies={replies} from={','.join(sorted(sources))}")


if __name__ == "__main__":
    {"listen": listen, "send": send}[sys.argv[1]](sys.argv[2:])
