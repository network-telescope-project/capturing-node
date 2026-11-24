#include "packet.hpp"

#include <cstring>

namespace nt {

const uint8_t* skip_link_header(int linktype, const uint8_t* frame, uint32_t caplen, uint32_t& ip_caplen) {
    uint32_t off = 0;
    uint16_t proto = 0;
    switch (linktype) {
        case kLinkEthernet:
            off = 14;
            if (caplen < off) return nullptr;
            proto = rd16(frame + 12);
            while (proto == 0x8100 || proto == 0x88a8 || proto == 0x9100) {  // VLAN tags
                if (caplen < off + 4) return nullptr;
                proto = rd16(frame + off + 2);
                off += 4;
            }
            break;
        case kLinkLinuxSll:
            off = 16;
            if (caplen < off) return nullptr;
            proto = rd16(frame + 14);
            break;
        case kLinkLinuxSll2:
            off = 20;
            if (caplen < off) return nullptr;
            proto = rd16(frame);
            break;
        case kLinkRaw:
            if (caplen < 1 || (frame[0] >> 4) != 4) return nullptr;
            proto = 0x0800;
            break;
        default:
            return nullptr;
    }
    if (proto != 0x0800) return nullptr;
    ip_caplen = caplen - off;
    return frame + off;
}

ParseResult parse_ipv4_tcp(const uint8_t* ip, uint32_t caplen, TcpPacket& out) {
    if (caplen < 20 || (ip[0] >> 4) != 4) return ParseResult::kNotIpv4;
    uint8_t ihl = uint8_t((ip[0] & 0x0f) * 4);
    uint16_t total = rd16(ip + 2);
    if (ihl < 20 || total < ihl || caplen < ihl) return ParseResult::kMalformed;
    if (ip[9] != 6) return ParseResult::kNotTcp;
    uint16_t frag = rd16(ip + 6);
    if (frag & 0x3fff) return ParseResult::kFragment;  // MF set or offset != 0
    if (total < ihl + 20u || caplen < ihl + 20u) return ParseResult::kMalformed;
    const uint8_t* tcp = ip + ihl;
    uint8_t thl = uint8_t((tcp[12] >> 4) * 4);
    if (thl < 20 || total < ihl + thl || caplen < uint32_t(ihl + thl)) return ParseResult::kMalformed;

    out.ip = ip;
    out.ip_caplen = caplen < total ? caplen : total;
    out.ip_len = total;
    out.ip_id = rd16(ip + 4);
    out.ttl = ip[8];
    out.saddr = rd32(ip + 12);
    out.daddr = rd32(ip + 16);
    out.sport = rd16(tcp);
    out.dport = rd16(tcp + 2);
    out.seq = rd32(tcp + 4);
    out.ack = rd32(tcp + 8);
    out.flags = tcp[13];
    out.window = rd16(tcp + 14);
    out.ip_hl = ihl;
    out.tcp_hl = thl;
    out.payload_len = uint32_t(total - ihl - thl);
    out.tcp_opts = tcp + 20;
    out.tcp_opts_len = uint8_t(thl - 20);
    return ParseResult::kOk;
}

namespace {

struct SynOptions {
    bool sack_perm = false;
    bool wscale = false;
    bool ts = false;
    uint32_t ts_val = 0;
};

SynOptions parse_syn_options(const TcpPacket& syn) {
    SynOptions o;
    const uint8_t* p = syn.tcp_opts;
    size_t n = syn.tcp_opts_len, i = 0;
    while (i < n) {
        uint8_t kind = p[i];
        if (kind == 0) break;
        if (kind == 1) { ++i; continue; }
        if (i + 1 >= n || p[i + 1] < 2 || i + p[i + 1] > n) break;
        uint8_t len = p[i + 1];
        if (kind == 3 && len == 3) o.wscale = true;
        else if (kind == 4 && len == 2) o.sack_perm = true;
        else if (kind == 8 && len == 10) { o.ts = true; o.ts_val = rd32(p + i + 2); }
        i += len;
    }
    return o;
}

size_t build(uint8_t* buf, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq,
             uint32_t ack, uint8_t flags, uint16_t window, const uint8_t* opts, size_t opts_len, bool df,
             uint8_t ttl, uint16_t ip_id) {
    size_t tcp_len = 20 + opts_len;
    size_t total = 20 + tcp_len;
    uint8_t* ip = buf;
    std::memset(ip, 0, total);
    ip[0] = 0x45;
    wr16(ip + 2, uint16_t(total));
    wr16(ip + 4, ip_id);
    wr16(ip + 6, df ? 0x4000 : 0);
    ip[8] = ttl;
    ip[9] = 6;
    wr32(ip + 12, saddr);
    wr32(ip + 16, daddr);
    wr16(ip + 10, csum_fold(csum_add(0, ip, 20)));

    uint8_t* tcp = ip + 20;
    wr16(tcp, sport);
    wr16(tcp + 2, dport);
    wr32(tcp + 4, seq);
    wr32(tcp + 8, ack);
    tcp[12] = uint8_t((tcp_len / 4) << 4);
    tcp[13] = flags;
    wr16(tcp + 14, window);
    if (opts_len) std::memcpy(tcp + 20, opts, opts_len);

    uint8_t pseudo[12];
    wr32(pseudo, saddr);
    wr32(pseudo + 4, daddr);
    pseudo[8] = 0;
    pseudo[9] = 6;
    wr16(pseudo + 10, uint16_t(tcp_len));
    wr16(tcp + 16, csum_fold(csum_add(csum_add(0, pseudo, 12), tcp, tcp_len)));
    return total;
}

}  // namespace

size_t build_synack(uint8_t* buf, const TcpPacket& syn, const CraftParams& p, Rng& rng) {
    uint8_t opts[40];
    size_t n = 0;
    uint16_t window = 65535;
    bool df = false;
    if (p.profile == SynAckProfile::kRegular) {
        // Shaped like a Linux SYN-ACK: MSS always, SACK / timestamps / window scale only if the SYN offered them.
        SynOptions so = parse_syn_options(syn);
        window = 65160;
        df = true;
        opts[n++] = 2; opts[n++] = 4; wr16(opts + n, 1460); n += 2;
        if (so.sack_perm && so.ts) {
            opts[n++] = 4; opts[n++] = 2;
        } else if (so.ts || so.sack_perm) {
            opts[n++] = 1; opts[n++] = 1;
            if (!so.ts) { opts[n++] = 4; opts[n++] = 2; }
        }
        if (so.ts) {
            opts[n++] = 8; opts[n++] = 10;
            wr32(opts + n, rng.u32()); wr32(opts + n + 4, so.ts_val); n += 8;
        }
        if (so.wscale) { opts[n++] = 1; opts[n++] = 3; opts[n++] = 3; opts[n++] = 7; }
    }
    uint32_t ack = syn.seq + syn.payload_len + 1;  // as Spoki (shard.cpp)
    return build(buf, syn.daddr, syn.saddr, syn.dport, syn.sport, rng.u32(), ack, kSyn | kAck, window, opts, n, df,
                 p.ttl, uint16_t(rng.u32()));
}

size_t build_rst(uint8_t* buf, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq,
                 const CraftParams& p, Rng& rng) {
    // As Spoki's scamper tcp-rst patch: RST only, seq = the peer's ACK number, ack = 0 (window 0 is our choice).
    return build(buf, saddr, daddr, sport, dport, seq, 0, kRst, 0, nullptr, 0,
                 p.profile == SynAckProfile::kRegular, p.ttl, uint16_t(rng.u32()));
}

}  // namespace nt
