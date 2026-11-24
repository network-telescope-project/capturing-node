#include "pcap_io.hpp"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>

#include "packet.hpp"

namespace nt {

namespace {
constexpr uint32_t kMagicUs = 0xa1b2c3d4;
constexpr uint32_t kMagicNs = 0xa1b23c4d;
constexpr uint32_t kNgShb = 0x0a0d0d0a;
constexpr uint32_t kNgByteOrder = 0x1a2b3c4d;
constexpr uint32_t kNgIdb = 1, kNgSpb = 3, kNgEpb = 6;
constexpr uint32_t kMaxBlock = 16 * 1024 * 1024;

uint32_t bswap32(uint32_t v) { return __builtin_bswap32(v); }
}  // namespace

PcapReader::~PcapReader() {
    if (f_) std::fclose(f_);
}

uint16_t PcapReader::u16(const uint8_t* p) const {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return swapped_ ? __builtin_bswap16(v) : v;
}

uint32_t PcapReader::u32(const uint8_t* p) const {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return swapped_ ? bswap32(v) : v;
}

TimeNs PcapReader::to_ns(uint64_t units, uint64_t per_sec) const {
    if (per_sec == kNsPerSec) return units;
    return units / per_sec * kNsPerSec + units % per_sec * kNsPerSec / per_sec;
}

bool PcapReader::open(const std::string& path, std::string& err) {
    f_ = std::fopen(path.c_str(), "rb");
    if (!f_) { err = path + ": " + std::strerror(errno); return false; }
    uint8_t hdr[24];
    if (std::fread(hdr, 1, 4, f_) != 4) { err = path + ": too short"; return false; }
    uint32_t magic;
    std::memcpy(&magic, hdr, 4);
    if (magic == kNgShb) {
        ng_ = true;
        uint8_t rest[8];
        if (std::fread(rest, 1, 8, f_) != 8) { err = path + ": truncated section header"; return false; }
        uint32_t bom;
        std::memcpy(&bom, rest + 4, 4);
        if (bom == kNgByteOrder) swapped_ = false;
        else if (bom == bswap32(kNgByteOrder)) swapped_ = true;
        else { err = path + ": bad pcapng byte-order magic"; return false; }
        return read_section_header(u32(rest), err);
    }
    if (magic == kMagicUs || magic == kMagicNs) swapped_ = false;
    else if (magic == bswap32(kMagicUs) || magic == bswap32(kMagicNs)) swapped_ = true;
    else { err = path + ": not a pcap or pcapng file"; return false; }
    nano_ = (swapped_ ? bswap32(magic) : magic) == kMagicNs;
    if (std::fread(hdr + 4, 1, 20, f_) != 20) { err = path + ": truncated pcap header"; return false; }
    linktype_ = int(u32(hdr + 20) & 0x0fffffff);
    return true;
}

// The first 12 bytes of the SHB were consumed; skip the rest of it and forget the previous section's interfaces.
bool PcapReader::read_section_header(uint32_t block_len, std::string& err) {
    if (block_len < 28 || block_len > kMaxBlock || block_len % 4) { err = "bad pcapng section header length"; return false; }
    buf_.resize(block_len - 12);
    if (std::fread(buf_.data(), 1, buf_.size(), f_) != buf_.size()) { err = "truncated pcapng section header"; return false; }
    ifaces_.clear();
    return true;
}

bool PcapReader::next(FrameRecord& rec, std::string& err) {
    err.clear();
    return ng_ ? next_pcapng(rec, err) : next_classic(rec, err);
}

bool PcapReader::next_classic(FrameRecord& rec, std::string& err) {
    uint8_t h[16];
    size_t n = std::fread(h, 1, 16, f_);
    if (n == 0) return false;
    if (n != 16) { err = "truncated record header"; return false; }
    uint32_t caplen = u32(h + 8);
    if (caplen > kMaxBlock) { err = "record too large"; return false; }
    buf_.resize(caplen);
    if (std::fread(buf_.data(), 1, caplen, f_) != caplen) { err = "truncated record"; return false; }
    rec.ts = uint64_t(u32(h)) * kNsPerSec + uint64_t(u32(h + 4)) * (nano_ ? 1 : 1000);
    rec.linktype = linktype_;
    rec.data = buf_.data();
    rec.caplen = caplen;
    rec.wirelen = u32(h + 12);
    return true;
}

bool PcapReader::next_pcapng(FrameRecord& rec, std::string& err) {
    for (;;) {
        uint8_t h[8];
        size_t n = std::fread(h, 1, 8, f_);
        if (n == 0) return false;
        if (n != 8) { err = "truncated block header"; return false; }
        uint32_t type;
        std::memcpy(&type, h, 4);
        if (type == kNgShb) {
            // New section: may switch byte order.
            uint8_t bom_raw[4];
            if (std::fread(bom_raw, 1, 4, f_) != 4) { err = "truncated section header"; return false; }
            uint32_t bom;
            std::memcpy(&bom, bom_raw, 4);
            if (bom == kNgByteOrder) swapped_ = false;
            else if (bom == bswap32(kNgByteOrder)) swapped_ = true;
            else { err = "bad pcapng byte-order magic"; return false; }
            if (!read_section_header(u32(h + 4), err)) return false;
            continue;
        }
        type = u32(h);
        uint32_t len = u32(h + 4);
        if (len < 12 || len > kMaxBlock || len % 4) { err = "bad pcapng block length"; return false; }
        buf_.resize(len - 8);
        if (std::fread(buf_.data(), 1, buf_.size(), f_) != buf_.size()) { err = "truncated block"; return false; }
        const uint8_t* b = buf_.data();
        size_t body = buf_.size() - 4;  // without the trailing length

        if (type == kNgIdb) {
            if (body < 8) { err = "short interface block"; return false; }
            Interface itf{int(u16(b)), 1000000};
            size_t o = 8;
            while (o + 4 <= body) {
                uint16_t code = u16(b + o), olen = u16(b + o + 2);
                if (code == 0 || o + 4 + olen > body) break;
                if (code == 9 && olen >= 1) {  // if_tsresol
                    uint8_t r = b[o + 4];
                    uint64_t per = 1;
                    if (r & 0x80) per = (r & 0x7f) < 63 ? (1ULL << (r & 0x7f)) : 0;
                    else for (int i = 0; i < r && per <= kNsPerSec * 1000; ++i) per *= 10;
                    if (per == 0 || per > kNsPerSec * 1000) { err = "unsupported if_tsresol"; return false; }
                    itf.ts_units_per_sec = per;
                }
                o += 4 + ((olen + 3u) & ~3u);
            }
            ifaces_.push_back(itf);
        } else if (type == kNgEpb) {
            if (body < 20) { err = "short packet block"; return false; }
            uint32_t ifid = u32(b);
            if (ifid >= ifaces_.size()) { err = "packet for an unknown interface"; return false; }
            uint32_t caplen = u32(b + 12);
            if (20 + size_t(caplen) > body) { err = "packet block shorter than its capture length"; return false; }
            uint64_t units = uint64_t(u32(b + 4)) << 32 | u32(b + 8);
            rec.ts = last_ts_ = to_ns(units, ifaces_[ifid].ts_units_per_sec);
            rec.linktype = ifaces_[ifid].linktype;
            rec.data = b + 20;
            rec.caplen = caplen;
            rec.wirelen = u32(b + 16);
            return true;
        } else if (type == kNgSpb) {
            if (body < 4 || ifaces_.empty()) { err = "bad simple packet block"; return false; }
            uint32_t wirelen = u32(b);
            uint32_t caplen = uint32_t(body - 4) < wirelen ? uint32_t(body - 4) : wirelen;
            rec.ts = last_ts_;  // SPBs carry no timestamp
            rec.linktype = ifaces_[0].linktype;
            rec.data = b + 4;
            rec.caplen = caplen;
            rec.wirelen = wirelen;
            return true;
        }
        // other blocks (name resolution, statistics, ...) are skipped
    }
}

PcapWriter::PcapWriter(std::string dir, std::string prefix, uint32_t duration_s, uint32_t max_files)
    : dir_(std::move(dir)), prefix_(std::move(prefix)), duration_ns_(TimeNs(duration_s) * kNsPerSec),
      max_files_(max_files), iobuf_(1 << 20) {}

PcapWriter::~PcapWriter() { close(); }

bool PcapWriter::open_file(TimeNs ts) {
    ++seq_;
    time_t secs = time_t(ts / kNsPerSec);
    struct tm tm;
    localtime_r(&secs, &tm);  // dumpcap names its files in local time too
    char stamp[32], name[64];
    std::strftime(stamp, sizeof stamp, "%Y%m%d%H%M%S", &tm);
    std::snprintf(name, sizeof name, "%s_%05llu_%s.pcap", prefix_.c_str(), (unsigned long long)seq_, stamp);
    std::string path = dir_ + "/" + name;

    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0 || !(f_ = fdopen(fd, "wb"))) {
        err_ = path + ": " + std::strerror(errno);
        if (fd >= 0) ::close(fd);
        return false;
    }
    std::setvbuf(f_, iobuf_.data(), _IOFBF, iobuf_.size());
    // Native byte order (readers detect it from the magic): version 2.4, snaplen 65535, LINKTYPE_RAW.
    struct { uint32_t magic; uint16_t major, minor; int32_t zone; uint32_t sigfigs, snaplen, linktype; } hdr =
        {kMagicUs, 2, 4, 0, 0, 65535, kLinkRaw};
    static_assert(sizeof hdr == 24, "pcap file header");
    if (std::fwrite(&hdr, 1, 24, f_) != 24) { err_ = path + ": write failed"; return false; }
    file_start_ = ts;

    files_.push_back(path);
    while (max_files_ && files_.size() > max_files_) {
        ::unlink(files_.front().c_str());  // may already be gone (transferred)
        files_.pop_front();
    }
    return true;
}

void PcapWriter::rotate_if_due(TimeNs now) {
    if (f_ && now >= file_start_ + duration_ns_) close();
}

bool PcapWriter::write(TimeNs ts, const uint8_t* ip, uint32_t caplen, uint32_t wirelen) {
    rotate_if_due(ts);
    if (!f_ && !open_file(ts)) return false;
    uint32_t h[4] = {uint32_t(ts / kNsPerSec), uint32_t(ts % kNsPerSec / 1000), caplen, wirelen};
    if (std::fwrite(h, 1, 16, f_) != 16 || std::fwrite(ip, 1, caplen, f_) != caplen) {
        err_ = "write failed: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

void PcapWriter::close() {
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;
    }
}

}  // namespace nt
