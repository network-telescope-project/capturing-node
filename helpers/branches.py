#!/usr/bin/env python3
"""Branches of the telescope addresses: which ones the responder answers, and how.

  branches.py draw     <nets> [--mgmt ADDR] [--seed N]                           the random split, as lines for the env file
  branches.py check    <nets> --irregular LIST --regular LIST [--mgmt ADDR]      validate the lists, print the counts
  branches.py manifest <nets> --irregular LIST --regular LIST --seed N [--mgmt ADDR] --out-dir DIR
                                                                                 write the file sent to the processing node

Every address of <nets> (DARKNET_NETS) is in exactly one branch: passive (never answered), r-irregular (SYN-ACK
without TCP options, as Spoki) or r-regular (SYN-ACK like a Linux host). The split is random, 2 : 1 : 1, and made
inside groups of GROUP consecutive addresses, so that every part of the range gets all three branches (a plain random
draw can by chance put most answered addresses at one end, and scanners do prefer some positions).

Always passive: the node's own management address, and the addresses ending in .0, .1 and .255 (network, usual
gateway, broadcast: scanners treat them differently, so they are kept out of the comparison and flagged).

The draw is reproducible from the seed: inside a group the addresses are ordered by sha256("<seed>:<address>"),
the first quarter is r-irregular, the second quarter r-regular, the rest passive. A smaller last group rounds its quarter to
the nearest whole address (7 addresses: 3 passive, 2, 2; fewer than 3: all passive).
"""
import argparse
import hashlib
import ipaddress
import os
import secrets
import sys

sys.dont_write_bytecode = True

from darknet import parse_nets

GROUP = 8
SPECIAL_LAST_OCTETS = (0, 1, 255)
MAX_ADDRESSES = 4096        # the lists live in the env file; a larger scope needs another design
BRANCHES = ("passive", "r-irregular", "r-regular")
MANIFEST_HEADER = "# nt-branches v1"


def scope(nets):
    """All addresses of the monitored scope, sorted, as integers"""
    total = sum(n.num_addresses for n in nets)
    if total > MAX_ADDRESSES:
        sys.exit(f"{total} addresses in DARKNET_NETS: per-address branches support at most {MAX_ADDRESSES}")
    return sorted({int(a) for n in nets for a in n})


def parse_addr(text, what):
    try:
        return int(ipaddress.IPv4Address(text.strip()))
    except ValueError as e:
        sys.exit(f"invalid {what} '{text}': {e}")


def parse_list(text, what):
    return [parse_addr(t, what) for t in text.replace(",", " ").split()]


def flag_of(addr, mgmt):
    if addr == mgmt:
        return "mgmt"
    if addr & 0xFF in SPECIAL_LAST_OCTETS:
        return "special"
    return ""


def draw(addresses, mgmt, seed):
    """(r-irregular, r-regular) address lists of a random 2 : 1 : 1 split inside groups of GROUP consecutive usable addresses"""
    usable = [a for a in addresses if not flag_of(a, mgmt)]
    irregular, regular = [], []
    for i in range(0, len(usable), GROUP):
        group = sorted(usable[i:i + GROUP],
                       key=lambda a: hashlib.sha256(f"{seed}:{ipaddress.IPv4Address(a)}".encode()).digest())
        quarter = (len(group) + 1) // 4     # 7 left over: 3 passive, 2 + 2 answered
        irregular += group[:quarter]
        regular += group[quarter:2 * quarter]
    return sorted(irregular), sorted(regular)


def validate(addresses, irregular, regular, mgmt):
    """Exit with a message unless the lists are a valid assignment for the scope"""
    inside = set(addresses)
    seen = set()
    for name, addrs in (("R_IRREGULAR_ADDRS", irregular), ("R_REGULAR_ADDRS", regular)):
        for a in addrs:
            text = ipaddress.IPv4Address(a)
            if a not in inside:
                sys.exit(f"{name}: {text} is not in DARKNET_NETS")
            if a == mgmt:
                sys.exit(f"{name}: {text} is this node's management address, which is never answered for")
            if a in seen:
                sys.exit(f"{text} is listed twice in R_IRREGULAR_ADDRS / R_REGULAR_ADDRS")
            seen.add(a)


def fmt(addrs):
    return ",".join(str(ipaddress.IPv4Address(a)) for a in addrs)


def main(argv):
    p = argparse.ArgumentParser(prog="branches.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("draw", "check", "manifest"):
        s = sub.add_parser(name)
        s.add_argument("nets")
        s.add_argument("--mgmt", default="")
        if name == "draw":
            s.add_argument("--seed", type=int, default=0)
        else:
            s.add_argument("--irregular", default="")
            s.add_argument("--regular", default="")
        if name == "manifest":
            s.add_argument("--seed", type=int, default=0)
            s.add_argument("--out-dir", required=True)
    args = p.parse_args(argv[1:])

    nets = parse_nets(args.nets)
    if not nets:
        sys.exit("no address space given (DARKNET_NETS is empty)")
    addresses = scope(nets)
    mgmt = parse_addr(args.mgmt, "management address") if args.mgmt else None

    if args.cmd == "draw":
        seed = args.seed or secrets.randbelow(2 ** 32 - 1) + 1
        irregular, regular = draw(addresses, mgmt, seed)
        if not irregular:
            sys.exit(3)
        print(f"BRANCH_SEED={seed}")
        print(f"BRANCH_NETS={','.join(str(n) for n in nets)}")
        print(f"R_IRREGULAR_ADDRS={fmt(irregular)}")
        print(f"R_REGULAR_ADDRS={fmt(regular)}")
        return

    irregular = parse_list(args.irregular, "R_IRREGULAR_ADDRS entry")
    regular = parse_list(args.regular, "R_REGULAR_ADDRS entry")
    validate(addresses, irregular, regular, mgmt)
    branch = {**{a: "r-irregular" for a in irregular}, **{a: "r-regular" for a in regular}}

    if args.cmd == "check":
        flagged = sum(1 for a in addresses if flag_of(a, mgmt))
        print(f"{len(addresses) - len(branch)} passive ({flagged} of them always: management / .0 / .1 / .255), "
              f"{len(irregular)} r-irregular, {len(regular)} r-regular")
        return

    lines = [
        MANIFEST_HEADER,
        f"# seed={args.seed} group={GROUP} nets={','.join(str(n) for n in nets)}",
    ]
    lines += [f"{ipaddress.IPv4Address(a)}\t{branch.get(a, 'passive')}\t{flag_of(a, mgmt)}" for a in addresses]
    body = ("\n".join(lines) + "\n").encode()
    path = os.path.join(args.out_dir, f"branches_{hashlib.sha256(body).hexdigest()[:12]}.tsv")
    with open(path, "wb") as f:
        f.write(body)
    print(path)


if __name__ == "__main__":
    main(sys.argv)
