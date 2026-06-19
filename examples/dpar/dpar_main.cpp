// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// dpar — a worked example of Dynamic Parser Application Rules: read a rules file + a pcap/pcapng capture,
// and for every packet whose header fields match a rule, run the rule's parser over the selected payload
// region and tabulate the result. This file IS the "lib user brings their own parser" demo:
//
//   1. it defines a DOWNSTREAM parser Kind (OddTlvKind) on the lib's TLV cursors + the struct->SoA->Arrow
//      reflection — code that lives here, NOT in nanotins;
//   2. it composes that Kind into a parser_palette alongside the built-ins (someip_tlv, raw_tlv);
//   3. a CLI rule selects any of them by name, e.g.
//
//        udp.src_port == 0 && udp.dst_port == 9999 => oddtlv udp_payload "XYZtlv"
//
// Output is one NDJSON object per emitted row (per table) plus a --stats hit-counter summary, the analog of
// TCAM rule-hit counters. No Lance/Arrow sink is wired here (that is a follow-on); the rows are described
// structs, so an Arrow export is a drop-in via soatins.

#include "dpar_example.hpp"

#include "nanotins/pcap_blocks.hpp"

#include <cstdio>
#include <cstdlib>
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
                     "  rules: <node>.<field> <op> <value> [&& ...] => <parser> <region> \"<label>\"\n"
                     "  parsers: someip_tlv | raw_tlv | oddtlv   regions: udp_payload | tcp_payload | someip_payload\n");
        return 2;
    }

    std::vector<std::uint8_t> rules_bytes;
    if (!read_file(pos[0], rules_bytes)) {
        std::fprintf(stderr, "dpar: cannot open rules file %s\n", pos[0]);
        return 1;
    }
    std::vector<std::uint8_t> cap;
    if (!read_file(pos[1], cap)) {
        std::fprintf(stderr, "dpar: cannot open capture %s\n", pos[1]);
        return 1;
    }

    dpar_example::Engine engine;
    nanotins::dpar::CompileResult cr =
        engine.load_rules(std::string(rules_bytes.begin(), rules_bytes.end()));
    if (!cr.ok) {
        std::fprintf(stderr, "dpar: %zu rule error(s):\n", cr.errors.size());
        for (const std::string& e : cr.errors) {
            std::fprintf(stderr, "  %s\n", e.c_str());
        }
        return 1;
    }

    std::string err;
    std::vector<pcapblocks::BlockRef> refs;
    if (!pcapblocks::scan_blocks(pcapblocks::Bytes(cap.data(), cap.size()), refs, err)) {
        std::fprintf(stderr, "dpar: %s\n", err.c_str());
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

    // Dump every non-empty table as NDJSON (one object per row), labeled by Kind name.
    std::string out;
    engine.dump_ndjson(out);
    std::fwrite(out.data(), 1, out.size(), stdout);

    if (stats) {
        engine.dump_stats(stderr, cr.rules);
    }
    return 0;
}
