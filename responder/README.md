# nt-responder

Spoki-style active telescope (Hiesgen et al., USENIX Security 2022): answers TCP SYNs to `ACTIVE_NETS` with a
SYN-ACK, records the first payload and resets the connection. Design: `docs/responder/DESIGN.md` (project docs).

Status: P0/P1 - offline `replay` mode only (decision engine driven from pcap/pcapng files, nothing is sent).

## Build
```
./build.sh          # Docker (alpine), static binary -> bin/nt-responder
```

## Replay
```
bin/nt-responder replay --active-nets 198.51.100.0/24 --out-dir /tmp/out capture_*.pcap
```
Writes `active_<seq>_<ts>.pcap` (LINKTYPE_RAW, inbound packets to `ACTIVE_NETS` + the replies that would have been
sent) and prints counters. `nt-responder` without arguments lists all options.

## Rules (Spoki `shard.cpp`)
- SYN (no ACK, no RST): one SYN-ACK, unless a reply to the same (source IP, irregular?) is still waiting in the
  current send batch (Spoki: until Scamper confirmed the send); no queueing, no retransmission.
  Irregular = IP ID 54321 or TTL > 200 or no TCP options.
- ACK (no SYN, no RST): two RSTs (`--rst-count`) `--rst-delay` seconds later, seq = the peer's ACK number, once per
  peer endpoint (IP, port) at a time. A RST from the peer cancels it. The RSTs pass the same gate under the
  (source IP, regular) key and are dropped if a reply to it is still waiting.
- Everything else (FIN, SYN+ACK, ...) and bogon sources: recorded only.
