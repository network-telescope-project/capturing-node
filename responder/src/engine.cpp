#include "engine.hpp"

namespace nt {

std::string EngineStats::to_string() const {
    std::string s;
    auto add = [&s](const char* name, uint64_t v) { s += std::string(name) + "=" + std::to_string(v) + "\n"; };
    add("frames", frames);
    add("not_ipv4", not_ipv4);
    add("not_tcp", not_tcp);
    add("fragments", fragments);
    add("malformed", malformed);
    add("not_active", not_active);
    add("recorded", recorded);
    add("bogon_src", bogon_src);
    add("syn", syn);
    add("syn_irregular", syn_irregular);
    add("synack_sent", synack_sent);
    add("syn_gated", syn_gated);
    add("ack", ack);
    add("data_segments", data_segments);
    add("rst_scheduled", rst_scheduled);
    add("rst_already_scheduled", rst_already_scheduled);
    add("rst_cap_full", rst_cap_full);
    add("rst_sent", rst_sent);
    add("rst_gated", rst_gated);
    add("peer_rst", peer_rst);
    add("rst_cancelled", rst_cancelled);
    add("other", other);
    add("send_errors", send_errors);
    return s;
}

Engine::Engine(const EngineConfig& cfg, EngineOutput& out, uint64_t seed) : cfg_(cfg), out_(out), rng_(seed) {}

void Engine::send(TimeNs ts, const uint8_t* pkt, size_t len, uint64_t& counter) {
    if (!out_.transmit(pkt, len)) {
        ++stats_.send_errors;
        return;
    }
    ++counter;
    out_.record(ts, pkt, uint32_t(len), uint32_t(len));
}

bool Engine::claim_target(uint64_t key) {
    if (!pending_.insert(key).second) return false;
    pending_list_.push_back(key);
    return true;
}

void Engine::flush() {
    out_.flush();
    for (uint64_t key : pending_list_) pending_.erase(key);
    pending_list_.clear();
}

void Engine::advance(TimeNs now) {
    while (!rst_timers_.empty() && rst_timers_.front().due <= now) {
        RstTimer t = rst_timers_.front();
        rst_timers_.pop_front();
        auto it = rsts_.find(t.endpoint);
        if (it == rsts_.end() || it->second.gen != t.gen) continue;  // cancelled by a peer RST
        ScheduledRst r = it->second;
        rsts_.erase(it);
        uint32_t peer_ip = uint32_t(t.endpoint >> 16);
        // As Spoki: a reply to the same target is still queued -> this RST is dropped, not queued.
        if (!claim_target(target(peer_ip, false))) { ++stats_.rst_gated; continue; }
        uint8_t buf[kMaxReplyLen];
        for (uint32_t i = 0; i < cfg_.rst_count; ++i) {
            size_t len = build_rst(buf, r.our_ip, peer_ip, r.our_port, uint16_t(t.endpoint), r.seq, cfg_.craft, rng_);
            send(t.due, buf, len, stats_.rst_sent);
        }
    }
}

void Engine::on_frame(TimeNs now, int linktype, const uint8_t* frame, uint32_t caplen) {
    ++stats_.frames;
    uint32_t ip_caplen = 0;
    const uint8_t* ip = skip_link_header(linktype, frame, caplen, ip_caplen);
    if (!ip) { ++stats_.not_ipv4; return; }
    TcpPacket p;
    switch (parse_ipv4_tcp(ip, ip_caplen, p)) {
        case ParseResult::kOk: break;
        case ParseResult::kNotIpv4: ++stats_.not_ipv4; return;
        case ParseResult::kNotTcp: ++stats_.not_tcp; return;
        case ParseResult::kFragment: ++stats_.fragments; return;
        case ParseResult::kMalformed: ++stats_.malformed; return;
    }
    if (!cfg_.active.contains(p.daddr)) { ++stats_.not_active; return; }

    uint32_t keep = cfg_.payload_max ? uint32_t(p.ip_hl) + p.tcp_hl + cfg_.payload_max : p.ip_caplen;
    out_.record(now, p.ip, p.ip_caplen < keep ? p.ip_caplen : keep, p.ip_len);
    ++stats_.recorded;

    // Recorded, never answered: sources that cannot be real peers (incl. our own active addresses).
    if (bogon_sources().contains(p.saddr) || cfg_.active.contains(p.saddr)) { ++stats_.bogon_src; return; }

    if (p.has(kSyn) && !p.has(kAck) && !p.has(kRst)) {
        on_syn(now, p);
    } else if (!p.has(kSyn) && p.has(kAck) && !p.has(kRst)) {
        on_ack(now, p);
    } else if (p.has(kRst)) {
        ++stats_.peer_rst;
        if (rsts_.erase(endpoint(p.saddr, p.sport))) ++stats_.rst_cancelled;
    } else {
        ++stats_.other;  // FIN without ACK, SYN+ACK, NULL, ...: recorded only
    }
}

void Engine::on_syn(TimeNs now, const TcpPacket& p) {
    ++stats_.syn;
    bool irregular = p.irregular();
    if (irregular) ++stats_.syn_irregular;
    if (!claim_target(target(p.saddr, irregular))) { ++stats_.syn_gated; return; }  // not queued, just not answered
    uint8_t buf[kMaxReplyLen];
    size_t len = build_synack(buf, p, cfg_.craft, rng_);
    send(now, buf, len, stats_.synack_sent);
}

void Engine::on_ack(TimeNs now, const TcpPacket& p) {
    ++stats_.ack;
    if (p.payload_len) ++stats_.data_segments;
    uint64_t ep = endpoint(p.saddr, p.sport);
    if (rsts_.count(ep)) { ++stats_.rst_already_scheduled; return; }
    if (rsts_.size() >= cfg_.max_rst || rst_timers_.size() >= cfg_.max_rst) { ++stats_.rst_cap_full; return; }
    uint64_t gen = ++next_gen_;
    TimeNs due = now + cfg_.rst_delay;
    rsts_.emplace(ep, ScheduledRst{due, gen, p.ack, p.daddr, p.dport});
    rst_timers_.push_back({ep, due, gen});
    ++stats_.rst_scheduled;
}

}  // namespace nt
