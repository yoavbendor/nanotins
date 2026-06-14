// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// pcapng2json — a parser-only nanotins example: read a pcap/pcapng capture and print one JSON object per
// packet (NDJSON) with the decoded L2/L3/L4 layers. No Lance, no storage backend — just nanotins doing the
// scan + decode. (The nanolance project's pcapng2lance is the columnar/Lance counterpart.)

#include "pcapng2json.hpp"

#include <cstdio>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <input.pcap|pcapng>\n", argv[0]);
        std::fprintf(stderr, "       prints one JSON object per packet (NDJSON) to stdout.\n");
        return 2;
    }

    std::FILE* f = std::fopen(argv[1], "rb");
    if (!f) {
        std::fprintf(stderr, "pcapng2json: cannot open %s\n", argv[1]);
        return 1;
    }
    std::vector<std::uint8_t> bytes;
    std::uint8_t chunk[65536];
    std::size_t n = 0;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        bytes.insert(bytes.end(), chunk, chunk + n);
    }
    std::fclose(f);

    std::string out, err;
    if (!pcapng2json::to_ndjson(pcapblocks::Bytes(bytes.data(), bytes.size()), out, err)) {
        std::fprintf(stderr, "pcapng2json: %s\n", err.c_str());
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}
