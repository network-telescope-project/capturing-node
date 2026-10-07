#!/usr/bin/env python3
"""Helper for DARKNET_NETS, the destinations the capture keeps (a list of addresses and prefixes).

  darknet.py detect  <iface>         public addresses configured on the interface
  darknet.py missing <iface> <nets>  those of them that no entry of <nets> covers
  darknet.py filter  <nets>          the BPF destination expression for <nets>

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


def bpf_filter(nets):
    parts = [
        f"dst host {n.network_address}" if n.prefixlen == n.max_prefixlen else f"dst net {n}"
        for n in nets
    ]
    return "(" + " or ".join(parts) + ")"


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
        print(bpf_filter(nets))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
