// Offline input (classic pcap and pcapng) and the rotating classic-pcap output (active_<seq>_<ts>.pcap).
#pragma once

#include <cstdint>
#include <cstdio>
#include <deque>
#include <string>
#include <vector>

#include "net.hpp"

namespace nt {

struct FrameRecord {
    TimeNs ts = 0;
    int linktype = 0;
    const uint8_t* data = nullptr;  // valid until the next call to next()
    uint32_t caplen = 0;
    uint32_t wirelen = 0;
};

class PcapReader {
public:
    ~PcapReader();
    bool open(const std::string& path, std::string& err);
    // false at the end of the file or on an error (err is then non-empty)
    bool next(FrameRecord& rec, std::string& err);

private:
    struct Interface { int linktype; uint64_t ts_units_per_sec; };
    bool next_classic(FrameRecord& rec, std::string& err);
    bool next_pcapng(FrameRecord& rec, std::string& err);
    bool read_section_header(uint32_t block_len, std::string& err);
    uint16_t u16(const uint8_t* p) const;
    uint32_t u32(const uint8_t* p) const;
    TimeNs to_ns(uint64_t units, uint64_t per_sec) const;

    FILE* f_ = nullptr;
    bool ng_ = false;
    bool swapped_ = false;
    // classic
    int linktype_ = 0;
    bool nano_ = false;
    // pcapng
    std::vector<Interface> ifaces_;
    TimeNs last_ts_ = 0;
    std::vector<uint8_t> buf_;
};

// Writes LINKTYPE_RAW (IPv4) classic pcap files with microsecond timestamps, so that inbound packets and our
// replies share one link type. Starts a new file every `duration_s` seconds (by packet time) and, like dumpcap's
// `-b files:N`, keeps at most `max_files` of its own files (0 = no limit).
class PcapWriter {
public:
    PcapWriter(std::string dir, std::string prefix, uint32_t duration_s, uint32_t max_files);
    ~PcapWriter();
    bool write(TimeNs ts, const uint8_t* ip, uint32_t caplen, uint32_t wirelen);
    // Closes the current file once its duration has passed (live mode calls this from a timer).
    void rotate_if_due(TimeNs now);
    void close();
    uint64_t files_written() const { return seq_; }
    const std::string& error() const { return err_; }

private:
    bool open_file(TimeNs ts);

    std::string dir_, prefix_;
    TimeNs duration_ns_;
    uint32_t max_files_;
    FILE* f_ = nullptr;
    std::vector<char> iobuf_;
    TimeNs file_start_ = 0;
    uint64_t seq_ = 0;
    std::deque<std::string> files_;
    std::string err_;
};

}  // namespace nt
