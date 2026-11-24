#include "net.hpp"

#include <algorithm>
#include <cstdlib>

namespace nt {

std::string ip_to_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string(ip >> 16 & 255) + "." +
           std::to_string(ip >> 8 & 255) + "." + std::to_string(ip & 255);
}

static bool parse_ip(const std::string& s, uint32_t& out) {
    uint32_t ip = 0;
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (pos >= s.size() || s[pos] < '0' || s[pos] > '9') return false;
        uint32_t octet = 0;
        size_t start = pos;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9' && pos - start < 3)
            octet = octet * 10 + uint32_t(s[pos++] - '0');
        if (octet > 255) return false;
        ip = ip << 8 | octet;
        if (i < 3) {
            if (pos >= s.size() || s[pos] != '.') return false;
            ++pos;
        }
    }
    if (pos != s.size()) return false;
    out = ip;
    return true;
}

bool PrefixSet::parse(const std::string& text, std::string& err) {
    std::string token;
    auto flush = [&]() -> bool {
        if (token.empty()) return true;
        std::string addr = token;
        int len = 32;
        auto slash = token.find('/');
        if (slash != std::string::npos) {
            addr = token.substr(0, slash);
            std::string l = token.substr(slash + 1);
            char* end = nullptr;
            long v = l.empty() ? -1 : std::strtol(l.c_str(), &end, 10);
            if (v < 0 || v > 32 || *end != '\0') { err = "bad prefix length in '" + token + "'"; return false; }
            len = int(v);
        }
        uint32_t ip;
        if (!parse_ip(addr, ip)) { err = "bad IPv4 address in '" + token + "'"; return false; }
        uint32_t host_mask = len == 0 ? 0xffffffffu : (len == 32 ? 0 : (0xffffffffu >> len));
        if (ip & host_mask) { err = "'" + token + "' has host bits set (write the network address)"; return false; }
        add(ip, ip | host_mask);
        token.clear();
        return true;
    };
    for (char c : text) {
        if (c == ',' || c == ' ' || c == '\t' || c == '\n') {
            if (!flush()) return false;
        } else {
            token += c;
        }
    }
    return flush();
}

void PrefixSet::add(uint32_t first, uint32_t last) {
    ranges_.push_back({first, last});
    std::sort(ranges_.begin(), ranges_.end(), [](const Range& a, const Range& b) { return a.first < b.first; });
    std::vector<Range> merged;
    for (const auto& r : ranges_) {
        if (!merged.empty() && (merged.back().last == 0xffffffffu || r.first <= merged.back().last + 1))
            merged.back().last = std::max(merged.back().last, r.last);
        else
            merged.push_back(r);
    }
    ranges_.swap(merged);
}

bool PrefixSet::contains(uint32_t ip) const {
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), ip,
                               [](uint32_t v, const Range& r) { return v < r.first; });
    if (it == ranges_.begin()) return false;
    --it;
    return ip <= it->last;
}

std::string PrefixSet::to_string() const {
    std::string s;
    for (const auto& r : ranges_) {
        if (!s.empty()) s += ",";
        s += ip_to_string(r.first);
        if (r.last != r.first) s += "-" + ip_to_string(r.last);
    }
    return s;
}

const PrefixSet& bogon_sources() {
    static const PrefixSet set = [] {
        PrefixSet s;
        std::string err;
        s.parse("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 "
                "192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4", err);
        return s;
    }();
    return set;
}

uint32_t csum_add(uint32_t sum, const uint8_t* data, size_t len) {
    while (len > 1) {
        sum += uint32_t(data[0] << 8 | data[1]);
        data += 2;
        len -= 2;
    }
    if (len) sum += uint32_t(data[0] << 8);
    return sum;
}

uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}

}  // namespace nt
