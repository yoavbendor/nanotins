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

// ---- the single shared traversal (NANOTINS_HD): the ONE source of truth for serial emit, the bulk count
//      pass, and the bulk scatter pass — so the three can never disagree (serial == bulk == future gpu) ----

// Visit each child of one SRH at offset `off`: on_seg(segment_index, ptr-to-16-bytes) for every segment,
// then on_tlv(type, len) for every trailing TLV. All variable reads are clamped to the real packet end, so
// a truncated / over-claiming SRH yields a partial-but-bounded visit (never OOB). Device-safe.
template <class OnSeg, class OnTlv>
NANOTINS_HD inline void for_each_srh_child(const std::uint8_t* pkt, std::size_t off, std::size_t size,
                                           OnSeg on_seg, OnTlv on_tlv) noexcept {
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
        on_seg(static_cast<std::uint8_t>(i), s);
    }
    const std::uint8_t* tlv_start = seg_base + static_cast<std::size_t>(nseg) * 16u;
    if (tlv_start < end) {
        tlv_cursor c{tlv_start, end, tlv_pad::ipv6_options};
        tlv_record r{};
        while (c.next(r)) {
            on_tlv(r.type, r.length);
        }
    }
}

// Visit each option of a Hop-by-Hop / Destination-Options header at offset `off`: on_opt(type, len).
template <class OnOpt>
NANOTINS_HD inline void for_each_opt(const std::uint8_t* pkt, std::size_t off, std::size_t size,
                                     OnOpt on_opt) noexcept {
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
        on_opt(r.type, r.length);
    }
}

// ---- serial emission (host): the for_each callbacks push_back into the child tables -------------------
inline void emit_srh_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off, std::size_t size,
                              std::uint8_t srh_order, ipv6_child_tables& kids) {
    for_each_srh_child(
        pkt, off, size,
        [&](std::uint8_t idx, const std::uint8_t* s) {
            std::array<std::uint8_t, 16> addr{};
            std::memcpy(addr.data(), s, 16);
            kids.srh_segment.add(pid, srh_order, idx, addr);
        },
        [&](std::uint8_t type, std::uint8_t len) { kids.opt.add(pid, /*container=*/43, type, len); });
}
inline void emit_opt_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off, std::size_t size,
                              std::uint8_t container, ipv6_child_tables& kids) {
    for_each_opt(pkt, off, size,
                 [&](std::uint8_t type, std::uint8_t len) { kids.opt.add(pid, container, type, len); });
}

// ---- bulk primitives (NANOTINS_HD): count + POD sink + scatter, mirroring dag_bulk -------------------

// Per-packet child counts (count pass output); addable for the exclusive prefix-sum.
struct ipv6_child_counts {
    std::uint32_t seg = 0;
    std::uint32_t opt = 0;
    NANOTINS_HD ipv6_child_counts operator+(const ipv6_child_counts& o) const noexcept {
        return {seg + o.seg, opt + o.opt};
    }
};

// Count a packet's child rows by re-walking the graph and the same for_each traversals the scatter uses,
// so count == scattered rows exactly. No writes; device-safe.
template <class Graph>
NANOTINS_HD inline ipv6_child_counts count_packet_ipv6_children(int root, const std::uint8_t* p,
                                                                std::size_t size) noexcept {
    ipv6_child_counts c{};
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv6RoutingNode>) {
            for_each_srh_child(
                p, off, size, [&](std::uint8_t, const std::uint8_t*) { ++c.seg; },
                [&](std::uint8_t, std::uint8_t) { ++c.opt; });
        } else if constexpr (std::is_same_v<N, Ipv6HopByHopNode> || std::is_same_v<N, Ipv6DestOptNode>) {
            for_each_opt(p, off, size, [&](std::uint8_t, std::uint8_t) { ++c.opt; });
        }
    });
    return c;
}

// POD sink: raw column pointers into the (pre-sized) child tables. seg_addr is a flat 16-bytes-per-row
// buffer (a std::array<uint8,16> vector reinterpreted). Trivially copyable -> a GPU kernel can capture it.
struct ipv6_child_sink {
    std::uint64_t* seg_pid;
    std::uint8_t* seg_order;
    std::uint8_t* seg_index;
    std::uint8_t* seg_addr;  // row i at seg_addr + i*16
    std::uint64_t* opt_pid;
    std::uint8_t* opt_container;
    std::uint8_t* opt_type;
    std::uint8_t* opt_len;
};

// Re-walk a packet and write each child row to base + its own emit order (the exclusive-scan slot). Every
// index derives solely from this packet's base + emit order, so packets never collide: identical output
// serially, on a CPU pool, or (later) on the GPU. Device-safe.
template <class Graph>
NANOTINS_HD inline void scatter_packet_ipv6_children(std::uint64_t pid, int root, const std::uint8_t* p,
                                                     std::size_t size, ipv6_child_counts base,
                                                     const ipv6_child_sink& sink) noexcept {
    std::uint32_t seg = base.seg;
    std::uint32_t opt = base.opt;
    std::uint8_t srh_order = 0;
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv6RoutingNode>) {
            const std::uint8_t order = srh_order++;
            for_each_srh_child(
                p, off, size,
                [&](std::uint8_t idx, const std::uint8_t* s) {
                    sink.seg_pid[seg] = pid;
                    sink.seg_order[seg] = order;
                    sink.seg_index[seg] = idx;
                    std::memcpy(sink.seg_addr + std::size_t{seg} * 16u, s, 16);
                    ++seg;
                },
                [&](std::uint8_t type, std::uint8_t len) {
                    sink.opt_pid[opt] = pid;
                    sink.opt_container[opt] = 43;
                    sink.opt_type[opt] = type;
                    sink.opt_len[opt] = len;
                    ++opt;
                });
        } else if constexpr (std::is_same_v<N, Ipv6HopByHopNode> || std::is_same_v<N, Ipv6DestOptNode>) {
            const std::uint8_t container = std::is_same_v<N, Ipv6HopByHopNode> ? std::uint8_t{0} : std::uint8_t{60};
            for_each_opt(p, off, size, [&](std::uint8_t type, std::uint8_t len) {
                sink.opt_pid[opt] = pid;
                sink.opt_container[opt] = container;
                sink.opt_type[opt] = type;
                sink.opt_len[opt] = len;
                ++opt;
            });
        }
    });
}

static_assert(std::is_trivially_copyable_v<ipv6_child_sink>, "ipv6_child_sink must be POD for GPU capture");
static_assert(std::is_trivially_copyable_v<ipv6_child_counts>, "ipv6_child_counts must be POD");

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
