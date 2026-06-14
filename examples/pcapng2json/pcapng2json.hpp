// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// pcapng2json core: turn a pcap/pcapng capture into NDJSON (one JSON object per packet), decoding
// L2/L3/L4 with nanotins and nothing else — no Lance, no storage backend. This is the parser-only
// counterpart to nanolance's pcapng2lance: it shows the same scan (pcap_blocks) + decode (walk_packet
// over the L2/L3/L4 overlays) producing human-readable output instead of columnar Lance tables.
//
// The conversion is a free function over a byte span so it can be unit-tested in-process (see
// test_pcapng2json.cpp) without spawning the CLI.

#include "nanotins/pcap_blocks.hpp"
#include "nanotins/protocol_decode.hpp"
#include "nanotins/protocols.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace pcapng2json {

namespace detail {

inline void append_u64(std::string& s, const char* key, std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
    s += '"';
    s += key;
    s += "\":";
    s += buf;
}

inline std::string hex16(std::uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", v);
    return buf;
}

inline std::string mac(const std::array<std::uint8_t, 6>& a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

inline std::string ipv4(const std::array<std::uint8_t, 4>& a) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    return buf;
}

inline std::string ipv6(const std::array<std::uint8_t, 16>& a) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13],
                  a[14], a[15]);
    return buf;
}

// Accumulates the comma-separated objects of the per-packet "layers" array.
struct LayerList {
    std::string s;
    bool first = true;
    void open() {
        if (!first) s += ',';
        first = false;
        s += '{';
    }
};

}  // namespace detail

// Convert a whole capture (already in memory) to NDJSON. Returns false + err on a scan error; partial
// per-packet decode failures (truncated headers) just yield fewer "layers" for that packet.
inline bool to_ndjson(pcapblocks::Bytes file, std::string& out, std::string& err) {
    using namespace detail;
    out.clear();
    err.clear();

    std::vector<pcapblocks::BlockRef> refs;
    if (!pcapblocks::scan_blocks(file, refs, err)) {
        return false;
    }

    std::vector<std::uint16_t> iface_link;  // link_type per interface, reset at each section (SHB)
    std::uint64_t packet_id = 0;

    for (const pcapblocks::BlockRef& ref : refs) {
        if (ref.kind == pcapblocks::Kind::Shb) {
            iface_link.clear();
            continue;
        }
        if (ref.kind == pcapblocks::Kind::Idb) {
            pcapblocks::IdbView idb{};
            if (pcapblocks::parse_idb(file, ref, idb)) {
                iface_link.push_back(idb.link_type);
            }
            continue;
        }
        if (ref.kind != pcapblocks::Kind::Epb && ref.kind != pcapblocks::Kind::PcapRecord) {
            continue;
        }

        pcapblocks::EpbView e{};
        if (!pcapblocks::parse_epb(file, ref, e)) {
            continue;
        }
        const std::uint16_t link_type =
            e.interface_id < iface_link.size() ? iface_link[e.interface_id] : std::uint16_t{0};

        std::string line = "{";
        append_u64(line, "packet_id", packet_id);
        line += ',';
        append_u64(line, "interface_id", e.interface_id);
        line += ',';
        append_u64(line, "timestamp_raw", e.ts_raw);
        line += ',';
        append_u64(line, "caplen", e.caplen);
        line += ',';
        append_u64(line, "origlen", e.origlen);
        line += ',';
        append_u64(line, "link_type", link_type);

        // Decode L2/L3/L4 with the same walk the Lance converter uses; emit one object per layer.
        const protocols::Bytes pkt(file.data() + e.payload_file_offset, e.caplen);
        LayerList layers;
        protocols::walk_packet(
            link_type, pkt,
            [&](const protocols::Ethernet& x) {
                layers.open();
                layers.s += "\"type\":\"ethernet\",\"dst\":\"" + mac(x.dst) + "\",\"src\":\"" + mac(x.src) +
                            "\",\"ethertype\":\"" + hex16(x.ethertype.host()) + "\"}";
            },
            [&](const protocols::VlanTag& x) {
                layers.open();
                layers.s += "\"type\":\"vlan\",";
                append_u64(layers.s, "vid", x.tci.word_host() & 0x0FFFU);
                layers.s += ",\"inner_ethertype\":\"" + hex16(x.inner_ethertype.host()) + "\"}";
            },
            [&](const protocols::Ipv4& x) {
                layers.open();
                layers.s += "\"type\":\"ipv4\",\"src\":\"" + ipv4(x.src) + "\",\"dst\":\"" + ipv4(x.dst) + "\",";
                append_u64(layers.s, "protocol", x.protocol);
                layers.s += ',';
                append_u64(layers.s, "ttl", x.ttl);
                layers.s += ',';
                append_u64(layers.s, "total_length", x.total_length.host());
                layers.s += '}';
            },
            [&](const protocols::Ipv6& x) {
                layers.open();
                layers.s += "\"type\":\"ipv6\",\"src\":\"" + ipv6(x.src) + "\",\"dst\":\"" + ipv6(x.dst) + "\",";
                append_u64(layers.s, "next_header", x.next_header);
                layers.s += ',';
                append_u64(layers.s, "hop_limit", x.hop_limit);
                layers.s += '}';
            },
            [&](const protocols::Tcp& x) {
                layers.open();
                layers.s += "\"type\":\"tcp\",";
                append_u64(layers.s, "src_port", x.src_port.host());
                layers.s += ',';
                append_u64(layers.s, "dst_port", x.dst_port.host());
                layers.s += '}';
            },
            [&](const protocols::Udp& x) {
                layers.open();
                layers.s += "\"type\":\"udp\",";
                append_u64(layers.s, "src_port", x.src_port.host());
                layers.s += ',';
                append_u64(layers.s, "dst_port", x.dst_port.host());
                layers.s += '}';
            });

        line += ",\"layers\":[" + layers.s + "]}";
        out += line;
        out += '\n';
        ++packet_id;
    }
    return true;
}

}  // namespace pcapng2json
