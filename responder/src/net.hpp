// Small IPv4 helpers shared by the parser, the packet builder and the engine.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nt {

using TimeNs = uint64_t;  // nanoseconds since the Unix epoch
constexpr TimeNs kNsPerSec = 1000000000ULL;

inline uint16_t rd16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
inline uint32_t rd32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
inline void wr16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline void wr32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

std::string ip_to_string(uint32_t ip);

// A set of IPv4 ranges (merged, sorted), looked up by binary search.
class PrefixSet {
public:
    // Comma or space separated addresses / prefixes. Like helpers/darknet.py, a prefix must be
    // written as its network (no host bits). Returns false and sets err on a bad entry.
    bool parse(const std::string& text, std::string& err);
    void add(uint32_t first, uint32_t last);
    bool contains(uint32_t ip) const;
    bool empty() const { return ranges_.empty(); }
    std::string to_string() const;

private:
    struct Range { uint32_t first, last; };
    std::vector<Range> ranges_;
};

// Sources we never answer: private, loopback, link-local, CGNAT, multicast, reserved.
const PrefixSet& bogon_sources();

// Internet checksum helpers.
uint32_t csum_add(uint32_t sum, const uint8_t* data, size_t len);
uint16_t csum_fold(uint32_t sum);

// splitmix64: fast, good enough for ISNs and IP IDs (not a security boundary).
class Rng {
public:
    explicit Rng(uint64_t seed) : s_(seed) {}
    uint64_t next() {
        uint64_t z = (s_ += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    uint32_t u32() { return uint32_t(next() >> 32); }

private:
    uint64_t s_;
};

}  // namespace nt
