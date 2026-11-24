#!/usr/bin/env python3
"""Helper for DARKNET_NETS, the destinations the capture keeps (a list of addresses and prefixes).

  darknet.py detect  <iface>         public addresses configured on the interface
  darknet.py missing <iface> <nets>  those of them that no entry of <nets> covers
  darknet.py same    <nets> <nets>   exit status 0 if both lists cover the same addresses, else 1
  darknet.py filter  <nets> [<mgmt address> [<mgmt ports>]]
                                     the BPF destination expression for <nets>

<nets> is comma or space separated. A bare address means that host only; a prefix must be written
as its network (66.245.204.0/23), not as a host with its subnet length (66.245.205.231/23 would
silently capture the whole neighbouring subnet, so it is rejected).
"""
import ipaddress
import json
import subprocess
import sys


def parse_nets(text):
    nets = []
    for token in text.replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(token, strict=True))
        except ValueError as e:
            sys.exit(f"invalid DARKNET_NETS entry '{token}': {e}")
    return nets


def detect(iface):
    try:
        out = subprocess.run(
            ["ip", "-j", "addr", "show", "dev", iface, "scope", "global"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit(f"cannot read the addresses of '{iface}': {e}")

    found = []
    for link in json.loads(out or "[]"):
        for info in link.get("addr_info", []):
            local_ip = info.get("local")
            if not local_ip or info.get("temporary") or info.get("deprecated") or info.get("tentative"):
                continue
            addr = ipaddress.ip_address(local_ip)
            if addr.is_global and str(addr) not in found:
                found.append(str(addr))
    return found


SYN_ONLY = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"


def bpf_filter(nets, mgmt="", mgmt_ports=""):
    parts = [
        f"dst host {n.network_address}" if n.prefixlen == n.max_prefixlen else f"dst net {n}"
        for n in nets
    ]
    dst = "(" + " or ".join(parts) + ")"
    if not mgmt:
        return dst
    try:
        addr = ipaddress.ip_address(mgmt)
        ports = [int(p) for p in mgmt_ports.replace(",", " ").split()]
    except ValueError as e:
        sys.exit(f"invalid management address or port: {e}")
    if any(not 0 < p < 65536 for p in ports):
        sys.exit(f"invalid management port in '{mgmt_ports}'")
    if not any(addr in n for n in nets):
        return dst      # not monitored, nothing to exclude
    kept = SYN_ONLY
    if ports:
        kept += " and not (" + " or ".join(f"dst port {p}" for p in ports) + ")"
    return f"({dst} and (not dst host {addr} or ({kept})))"


def main(argv):
    if len(argv) >= 3 and argv[1] == "detect":
        print(",".join(detect(argv[2])))
    elif len(argv) >= 3 and argv[1] == "missing":
        nets = parse_nets(argv[3] if len(argv) > 3 else "")
        print(",".join(a for a in detect(argv[2]) if not any(ipaddress.ip_address(a) in n for n in nets)))
    elif len(argv) >= 3 and argv[1] == "filter":
        nets = parse_nets(argv[2])
        if not nets:
            sys.exit("no destination given")
        print(bpf_filter(nets, *argv[3:5]))
    elif len(argv) == 4 and argv[1] == "same":
        a, b = (list(ipaddress.collapse_addresses(parse_nets(text))) for text in argv[2:4])
        sys.exit(0 if a == b else 1)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
