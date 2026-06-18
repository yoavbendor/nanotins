// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// IPv6 variable-length child records: the SRv6 segment list and the Hop-by-Hop / Destination-Options /
// SRH TLV options. These do NOT fit "one row per DAG node" (a single SRH carries N segments + M TLVs), so
// they go into their own child tables keyed by packet_id — exactly how the `vlan` table stores 0..N tags.
// This is the SRv6TlvIterator pattern (tlv.hpp) applied to every IPv6 TLV space; see
// docs/the_case_for_learning_from_vbvx.md and docs/plan_ipv6_extension_headers_tlv.md (Phase 4).
//
// The locate/iterate primitives (struct_view, repeat_at, tlv_cursor) are NANOTINS_HD; the table growth here
// (std::vector::push_back) is host-only — Phase 5 brings the same primitives to the device bulk path.

#include "nanotins/dag_decode.hpp"
#include "nanotins/spec_dag.hpp"
#include "nanotins/tlv.hpp"
#include "nanotins/wire_spec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tuple>
#include <type_traits>
#include <vector>

namespace nanotins {

using namespace literals;

// ---- child tables (SoA, host accumulators) -----------------------------------------------------------

// One row per SRv6 segment: which packet, which SRH within the packet, which index within that SRH's list,
// and the 16-byte IPv6 address (-> Arrow fixed_size_binary(16) when written).
struct ipv6_srh_segment_table {
    std::vector<std::uint64_t> packet_id;
    std::vector<std::uint8_t> srh_order;       // 0,1,... per SRH header within the packet
    std::vector<std::uint8_t> segment_index;   // index within this SRH's segment list (0 = SegmentList[0])
    std::vector<std::array<std::uint8_t, 16>> address;
    std::size_t size() const { return packet_id.size(); }
    void add(std::uint64_t pid, std::uint8_t order, std::uint8_t idx, const std::array<std::uint8_t, 16>& a) {
        packet_id.push_back(pid);
        srh_order.push_back(order);
        segment_index.push_back(idx);
        address.push_back(a);
    }
};

// One row per IPv6 option / SRH TLV: which packet, the containing header's type (0 Hop-by-Hop, 60
// Destination Options, 43 SRH), and the option's type + value length.
struct ipv6_opt_table {
    std::vector<std::uint64_t> packet_id;
    std::vector<std::uint8_t> container_type;  // 0 | 60 | 43
    std::vector<std::uint8_t> opt_type;
    std::vector<std::uint8_t> opt_len;
    std::size_t size() const { return packet_id.size(); }
    void add(std::uint64_t pid, std::uint8_t container, std::uint8_t type, std::uint8_t len) {
        packet_id.push_back(pid);
        container_type.push_back(container);
        opt_type.push_back(type);
        opt_len.push_back(len);
    }
};

struct ipv6_child_tables {
    ipv6_srh_segment_table srh_segment;
    ipv6_opt_table opt;
};

// ---- per-header child emission (host; uses the NANOTINS_HD locate/iterate primitives) -----------------

// Emit one SRH's segments + trailing TLVs. `off` is the SRH's offset in `pkt`; the 8-byte fixed part is
// already known to fit (the DAG fit-checked it before the visit). All variable reads are clamped to the
// real packet end, so a truncated/over-claiming SRH yields a partial-but-bounded result (never OOB).
inline void emit_srh_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off, std::size_t size,
                              std::uint8_t srh_order, ipv6_child_tables& kids) {
    const std::uint8_t* p = pkt + off;
    const std::size_t srh_len =
        (static_cast<std::size_t>(struct_view<Ipv6SrhSpec>(p)("hdr_ext_len"_fld)) + 1u) * 8u;
    const std::size_t end_off = (off + srh_len <= size) ? (off + srh_len) : size;  // clamp to packet
    const std::uint8_t* end = pkt + end_off;
    const std::uint32_t nseg = static_cast<std::uint32_t>(struct_view<Ipv6SrhSpec>(p)("last_entry"_fld)) + 1u;
    const std::uint8_t* seg_base = p + 8;
    for (std::uint32_t i = 0; i < nseg; ++i) {
        const std::uint8_t* s = repeat_at(seg_base, nseg, 16, end, i);
        if (s == nullptr) {
            break;  // remaining segments don't fit -> stop (bounds-safe)
        }
        std::array<std::uint8_t, 16> addr{};
        std::memcpy(addr.data(), s, 16);
        kids.srh_segment.add(pid, srh_order, static_cast<std::uint8_t>(i), addr);
    }
    // Trailing SRH TLVs (after the segment list), if any.
    const std::uint8_t* tlv_start = seg_base + static_cast<std::size_t>(nseg) * 16u;
    if (tlv_start < end) {
        tlv_cursor c{tlv_start, end, tlv_pad::ipv6_options};
        tlv_record r{};
        while (c.next(r)) {
            kids.opt.add(pid, /*container=*/43, r.type, r.length);
        }
    }
}

// Emit the options of a Hop-by-Hop (container 0) or Destination Options (container 60) header.
inline void emit_opt_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off, std::size_t size,
                              std::uint8_t container, ipv6_child_tables& kids) {
    const std::uint8_t* p = pkt + off;
    const std::size_t hdr_len =
        (static_cast<std::size_t>(struct_view<Ipv6ExtOptSpec>(p)("hdr_ext_len"_fld)) + 1u) * 8u;
    const std::size_t end_off = (off + hdr_len <= size) ? (off + hdr_len) : size;  // clamp to packet
    const std::uint8_t* end = pkt + end_off;
    const std::uint8_t* start = p + 2;  // after [next_header][hdr_ext_len]
    if (start >= end) {
        return;
    }
    tlv_cursor c{start, end, tlv_pad::ipv6_options};
    tlv_record r{};
    while (c.next(r)) {
        kids.opt.add(pid, container, r.type, r.length);
    }
}

// Decode one packet's fixed per-node tables AND its IPv6 child records in a single walk (lockstep with the
// DAG). The fixed-row append is identical to dag_decode_packet; the child emission fires only for the IPv6
// SRH / Hop-by-Hop / Destination-Options nodes (compile-time dispatch, so other graphs are unaffected).
template <class Graph>
void dag_decode_packet_with_children(std::uint64_t packet_id, const std::uint8_t* pkt, std::size_t size,
                                     dag_tables<Graph>& tabs, ipv6_child_tables& kids, int root = 0) {
    std::uint8_t srh_order = 0;
    walk<Graph>(root, pkt, size, [&](auto Ic, std::size_t off) {
        constexpr std::size_t I = decltype(Ic)::value;
        std::get<I>(tabs).append(packet_id, pkt + off);  // the fixed per-node row (== dag_decode_packet)
        using N = std::tuple_element_t<I, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv6RoutingNode>) {
            emit_srh_children(packet_id, pkt, off, size, srh_order++, kids);
        } else if constexpr (std::is_same_v<N, Ipv6HopByHopNode>) {
            emit_opt_children(packet_id, pkt, off, size, /*container=*/0, kids);
        } else if constexpr (std::is_same_v<N, Ipv6DestOptNode>) {
            emit_opt_children(packet_id, pkt, off, size, /*container=*/60, kids);
        }
    });
}

}  // namespace nanotins
