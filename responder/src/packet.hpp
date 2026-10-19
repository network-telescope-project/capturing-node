// Parsing of captured frames into IPv4/TCP fields, and building of our SYN-ACK / RST replies.
#pragma once

#include <cstddef>
#include <cstdint>

#include "net.hpp"

namespace nt {

// pcap link types the reader/parser understands
constexpr int kLinkEthernet = 1;
constexpr int kLinkRaw = 101;
constexpr int kLinkLinuxSll = 113;
constexpr int kLinkLinuxSll2 = 276;

enum TcpFlag : uint8_t { kFin = 0x01, kSyn = 0x02, kRst = 0x04, kPsh = 0x08, kAck = 0x10, kUrg = 0x20 };

struct TcpPacket {
    const uint8_t* ip = nullptr;   // start of the IPv4 header in the capture buffer
    uint32_t ip_caplen = 0;        // captured bytes from the IPv4 header on
    uint32_t ip_len = 0;           // IPv4 total length (on the wire)
    uint32_t saddr = 0, daddr = 0;
    uint16_t sport = 0, dport = 0;
    uint32_t seq = 0, ack = 0;
    uint16_t ip_id = 0;
    uint8_t ttl = 0;
    uint8_t flags = 0;
    uint16_t window = 0;
    uint8_t ip_hl = 0, tcp_hl = 0;  // header lengths in bytes
    uint32_t payload_len = 0;       // on the wire (may be more than was captured)
    const uint8_t* tcp_opts = nullptr;
    uint8_t tcp_opts_len = 0;

    // Spoki (packet.cpp): IP ID 54321 || TTL > 200 || no TCP options
    bool irregular() const { return ip_id == 54321 || ttl > 200 || tcp_hl == 20; }
    bool has(uint8_t f) const { return (flags & f) != 0; }
};

enum class ParseResult { kOk, kNotIpv4, kNotTcp, kFragment, kMalformed };

// Locates the IPv4 header behind the link layer header.
const uint8_t* skip_link_header(int linktype, const uint8_t* frame, uint32_t caplen, uint32_t& ip_caplen);

ParseResult parse_ipv4_tcp(const uint8_t* ip, uint32_t caplen, TcpPacket& out);

enum class SynAckProfile { kSpoki, kRegular };

struct CraftParams {
    SynAckProfile profile = SynAckProfile::kSpoki;
    uint8_t ttl = 64;
};

constexpr size_t kMaxReplyLen = 20 + 60;

// Both return the packet length; buf must hold kMaxReplyLen bytes.
size_t build_synack(uint8_t* buf, const TcpPacket& syn, const CraftParams& p, Rng& rng);
size_t build_rst(uint8_t* buf, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq,
                 const CraftParams& p, Rng& rng);

}  // namespace nt
