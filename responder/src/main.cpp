// nt-responder: Spoki-style reactive telescope (answers TCP SYNs to ACTIVE_NETS, resets after the first payload).
//
// replay: drives the decision engine from pcap/pcapng files instead of the network; nothing is sent, the replies
//         that would have been sent are written to the output pcaps together with the inbound packets.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/random.h>
#include <sys/stat.h>
#include <vector>

#include "engine.hpp"
#include "pcap_io.hpp"

namespace {

const char* kUsage =
    "usage: nt-responder replay [options] FILE...\n"
    "\n"
    "  --active-nets NETS       addresses/prefixes to answer for, comma separated (required)\n"
    "  --out-dir DIR            where active_<seq>_<ts>.pcap files are written (required)\n"
    "  --prefix NAME            output file name prefix (default active)\n"
    "  --duration S             start a new output file every S seconds (default 3600)\n"
    "  --files N                keep at most N output files, 0 = no limit (default 0)\n"
    "  --payload-max N          payload bytes kept per recorded packet, 0 = all (default 0)\n"
    "  --synack-profile P       irregular (no options, window 65535, as Spoki) | regular (Linux-like) (default irregular)\n"
    "  --ttl N                  TTL of our packets (default 64)\n"
    "  --rst-delay S            seconds from the peer's ACK to our RST (default 5)\n"
    "  --rst-count N            RSTs sent per connection (default 2)\n"
    "  --max-rst N              cap of the scheduled-RST set (default 1048576)\n"
    "  --seed N                 random seed for ISNs / IP IDs, 0 = random (default 0)\n";

[[noreturn]] void die(const std::string& msg) {
    std::fprintf(stderr, "nt-responder: %s\n", msg.c_str());
    std::exit(2);
}

uint64_t parse_uint(const std::string& opt, const char* v, uint64_t max) {
    char* end = nullptr;
    errno = 0;
    unsigned long long n = std::strtoull(v, &end, 10);
    if (errno || end == v || *end || v[0] == '-' || n > max) die("invalid value for " + opt + ": " + v);
    return n;
}

class ReplayOutput : public nt::EngineOutput {
public:
    explicit ReplayOutput(nt::PcapWriter& w) : writer_(w) {}
    bool transmit(const uint8_t*, size_t) override { return true; }
    void record(nt::TimeNs ts, const uint8_t* ip, uint32_t caplen, uint32_t wirelen) override {
        if (!writer_.write(ts, ip, caplen, wirelen)) die(writer_.error());
    }

private:
    nt::PcapWriter& writer_;
};

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2 || std::strcmp(argv[1], "replay") != 0) {
        std::fputs(kUsage, stderr);
        return 2;
    }

    nt::EngineConfig cfg;
    std::string out_dir, prefix = "active", active_text;
    uint32_t duration = 3600, max_files = 0;
    uint64_t seed = 0;
    std::vector<std::string> inputs;

    for (int i = 2; i < argc; ++i) {
        std::string opt = argv[i];
        if (opt.rfind("--", 0) != 0) { inputs.push_back(opt); continue; }
        if (i + 1 >= argc) die("missing value for " + opt);
        const char* v = argv[++i];
        if (opt == "--active-nets") active_text = v;
        else if (opt == "--out-dir") out_dir = v;
        else if (opt == "--prefix") prefix = v;
        else if (opt == "--duration") duration = uint32_t(parse_uint(opt, v, 86400 * 7));
        else if (opt == "--files") max_files = uint32_t(parse_uint(opt, v, 1000000));
        else if (opt == "--payload-max") cfg.payload_max = uint32_t(parse_uint(opt, v, 65535));
        else if (opt == "--ttl") cfg.craft.ttl = uint8_t(parse_uint(opt, v, 255));
        else if (opt == "--rst-count") cfg.rst_count = uint32_t(parse_uint(opt, v, 10));
        else if (opt == "--max-rst") cfg.max_rst = parse_uint(opt, v, 1ULL << 32);
        else if (opt == "--seed") seed = parse_uint(opt, v, ~0ULL);
        else if (opt == "--rst-delay") {
            char* end = nullptr;
            double s = std::strtod(v, &end);
            if (end == v || *end || !(s >= 0 && s <= 3600)) die("invalid value for --rst-delay: " + std::string(v));
            cfg.rst_delay = nt::TimeNs(s * 1e9);
        } else if (opt == "--synack-profile") {
            if (std::strcmp(v, "irregular") == 0) cfg.craft.profile = nt::SynAckProfile::kIrregular;
            else if (std::strcmp(v, "regular") == 0) cfg.craft.profile = nt::SynAckProfile::kRegular;
            else die("--synack-profile must be irregular or regular");
        } else {
            die("unknown option " + opt);
        }
    }

    std::string err;
    if (active_text.empty()) die("--active-nets is required");
    if (!cfg.active.parse(active_text, err)) die("--active-nets: " + err);
    if (cfg.active.empty()) die("--active-nets is empty");
    if (out_dir.empty()) die("--out-dir is required");
    struct stat st;
    if (stat(out_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) die(out_dir + " is not a directory");
    if (duration == 0) die("--duration must be > 0");
    if (inputs.empty()) die("no input files");
    if (seed == 0 && getrandom(&seed, sizeof seed, 0) != sizeof seed) die("getrandom failed");

    nt::PcapWriter writer(out_dir, prefix, duration, max_files);
    ReplayOutput out(writer);
    nt::Engine engine(cfg, out, seed);

    nt::TimeNs now = 0;
    for (const auto& path : inputs) {
        nt::PcapReader reader;
        if (!reader.open(path, err)) die(err);
        nt::FrameRecord rec;
        while (reader.next(rec, err)) {
            if (rec.ts > now) now = rec.ts;  // the timers need a clock that never goes back
            engine.advance(now);
            engine.on_frame(now, rec.linktype, rec.data, rec.caplen);
            engine.flush();  // replay: every frame is its own send batch
        }
        if (!err.empty()) die(path + ": " + err);
    }
    engine.drain();
    writer.close();

    std::fprintf(stdout, "active_nets=%s\nfiles_written=%llu\n%s", cfg.active.to_string().c_str(),
                 (unsigned long long)writer.files_written(), engine.stats().to_string().c_str());
    return 0;
}
