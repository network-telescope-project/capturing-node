#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "net.hpp"
#include "packet.hpp"

namespace nt {

struct EngineConfig {
    PrefixSet active;                  // ACTIVE_NETS: only packets to these addresses are recorded / answered
    CraftParams craft;
    TimeNs rst_delay = 5 * kNsPerSec;  // Spoki reset_delay
    uint32_t rst_count = 2;            // Spoki num_tcp_rst_probes
    uint32_t payload_max = 0;          // payload bytes kept per recorded packet, 0 = all (as Spoki)
    size_t max_rst = 1 << 20;          // cap of the scheduled-RST set; when full, no RST is scheduled
};

// Where the engine's packets go: the network (raw socket in live mode, nothing in replay) and the pcap writer.
// transmit() may queue; flush() sends what was queued.
class EngineOutput {
public:
    virtual ~EngineOutput() = default;
    virtual bool transmit(const uint8_t* ip, size_t len) = 0;
    virtual void flush() {}
    virtual void record(TimeNs ts, const uint8_t* ip, uint32_t caplen, uint32_t wirelen) = 0;
};

struct EngineStats {
    uint64_t frames = 0, not_ipv4 = 0, not_tcp = 0, fragments = 0, malformed = 0, not_active = 0;
    uint64_t recorded = 0, bogon_src = 0;
    uint64_t syn = 0, syn_irregular = 0, synack_sent = 0, syn_gated = 0;
    uint64_t ack = 0, data_segments = 0, rst_scheduled = 0, rst_already_scheduled = 0, rst_cap_full = 0;
    uint64_t rst_sent = 0, rst_gated = 0, peer_rst = 0, rst_cancelled = 0, other = 0, send_errors = 0;
    std::string to_string() const;
};

class Engine {
public:
    Engine(const EngineConfig& cfg, EngineOutput& out, uint64_t seed);

    // Fires the RSTs that are due at `now`; call before on_frame with the frame's time.
    void advance(TimeNs now);
    void on_frame(TimeNs now, int linktype, const uint8_t* frame, uint32_t caplen);
    // Sends the queued replies and releases their targets (Spoki: "until Scamper confirms that it sent out the reply").
    void flush();
    // Fires all remaining RSTs (end of an offline replay).
    void drain() {
        advance(~TimeNs(0));
        flush();
    }

    const EngineStats& stats() const { return stats_; }

private:
    // Spoki's endpoint key: the peer's (IP, port), so a peer gets at most rst_count RSTs per rst_delay per port.
    static uint64_t endpoint(uint32_t ip, uint16_t port) { return uint64_t(ip) << 16 | port; }
    // Spoki's target_key {scanner IP, irregular?}; RSTs use the regular key, as Spoki's manager does.
    static uint64_t target(uint32_t ip, bool irregular) { return uint64_t(ip) << 1 | (irregular ? 1 : 0); }

    struct ScheduledRst { TimeNs due; uint64_t gen; uint32_t seq; uint32_t our_ip; uint16_t our_port; };
    struct RstTimer { uint64_t endpoint; TimeNs due; uint64_t gen; };

    bool claim_target(uint64_t key);
    void on_syn(TimeNs now, const TcpPacket& p);
    void on_ack(TimeNs now, const TcpPacket& p);
    void send(TimeNs ts, const uint8_t* pkt, size_t len, uint64_t& counter);

    EngineConfig cfg_;
    EngineOutput& out_;
    Rng rng_;
    EngineStats stats_;

    // targets with a reply queued since the last flush (no queueing of a second probe to the same target)
    std::unordered_set<uint64_t> pending_;
    std::vector<uint64_t> pending_list_;
    // scheduled RSTs per peer endpoint; due times are FIFO because rst_delay is constant
    std::unordered_map<uint64_t, ScheduledRst> rsts_;
    std::deque<RstTimer> rst_timers_;
    uint64_t next_gen_ = 0;
};

}  // namespace nt
