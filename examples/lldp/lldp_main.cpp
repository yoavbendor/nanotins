// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// lldp — apply an LLDP parser to a capture via DPAR rules and print one NDJSON object per LLDP TLV.
//
//   lldp [--stats] <rules.txt> <input.pcap|pcapng>
//
// The rules file says WHEN to apply the parser, e.g.:
//   eth.ethertype == 0x88CC => lldp eth_payload "lldp"
//
// This driver is the same shape as examples/dpar/dpar_main.cpp — only the example's palette (LLDP) and
// dumper differ. See lldp.hpp for the heavily-commented walkthrough of the parser + Kind.

#include "lldp.hpp"

#include "nanotins/pcap_blocks.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool read_file(const char* path, std::vector<std::uint8_t>& out) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) {
        return false;
    }
    std::uint8_t chunk[65536];
    std::size_t n = 0;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        out.insert(out.end(), chunk, chunk + n);
    }
    std::fclose(f);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    bool stats = false;
    std::vector<const char*> pos;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--stats") {
            stats = true;
        } else {
            pos.push_back(argv[i]);
        }
    }
    if (pos.size() < 2) {
        std::fprintf(stderr, "usage: %s [--stats] <rules.txt> <input.pcap|pcapng>\n", argv[0]);
        std::fprintf(stderr,
                     "  example rule: eth.ethertype == 0x88CC => lldp eth_payload \"lldp\"\n"
                     "  prints one NDJSON object per LLDP TLV to stdout.\n");
        return 2;
    }

    std::vector<std::uint8_t> rules_bytes;
    if (!read_file(pos[0], rules_bytes)) {
        std::fprintf(stderr, "lldp: cannot open rules file %s\n", pos[0]);
        return 1;
    }
    std::vector<std::uint8_t> cap;
    if (!read_file(pos[1], cap)) {
        std::fprintf(stderr, "lldp: cannot open capture %s\n", pos[1]);
        return 1;
    }

    lldp_example::Engine engine;
    nanotins::dpar::CompileResult cr =
        engine.load_rules(std::string(rules_bytes.begin(), rules_bytes.end()));
    if (!cr.ok) {
        std::fprintf(stderr, "lldp: %zu rule error(s):\n", cr.errors.size());
        for (const std::string& e : cr.errors) {
            std::fprintf(stderr, "  %s\n", e.c_str());
        }
        return 1;
    }

    std::string err;
    std::vector<pcapblocks::BlockRef> refs;
    if (!pcapblocks::scan_blocks(pcapblocks::Bytes(cap.data(), cap.size()), refs, err)) {
        std::fprintf(stderr, "lldp: %s\n", err.c_str());
        return 1;
    }

    std::uint64_t packet_id = 0;
    for (const pcapblocks::BlockRef& ref : refs) {
        if (ref.kind != pcapblocks::Kind::Epb && ref.kind != pcapblocks::Kind::PcapRecord) {
            continue;
        }
        pcapblocks::EpbView e{};
        if (!pcapblocks::parse_epb(pcapblocks::Bytes(cap.data(), cap.size()), ref, e)) {
            continue;
        }
        engine.run(cap.data() + e.payload_file_offset, e.caplen, packet_id);
        ++packet_id;
    }

    std::string out;
    engine.dump_ndjson(out);
    std::fwrite(out.data(), 1, out.size(), stdout);

    if (stats) {
        const nanotins::dpar::EngineStats& s = engine.stats();
        std::fprintf(stderr, "lldp stats: packets=%llu matched_any=%llu tlv_rows=%llu\n",
                     static_cast<unsigned long long>(s.packets_seen),
                     static_cast<unsigned long long>(s.packets_matched_any),
                     static_cast<unsigned long long>(s.rows_emitted));
    }
    return 0;
}
