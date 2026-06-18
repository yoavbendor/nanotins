// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// IPv4 variable-length child records: the options that live between the 20-byte fixed header and IHL*4 (RFC
// 791 3.1 — Record Route, Timestamp, Router Alert, Loose/Strict Source Route, ...). Like the IPv6
// Hop-by-Hop / Destination options, a single IPv4 header can carry 0..N options, so they do NOT fit
// "one row per DAG node" — they go into their own child table keyed by packet_id, exactly how
// ipv6_children.hpp stores the IPv6 options. This is the SRv6TlvIterator / tlv_cursor pattern (tlv.hpp)
// applied to the IPv4 option space.
//
// Unlike IPv6 extension headers (each its own DAG node), IPv4 options live INSIDE the IPv4 header, so the
// option walk hangs off the Ipv4Node itself: when the DAG walk visits Ipv4Node, the option region is
// [base + 20, base + IHL*4) and is walked with tlv_pad::ipv4_options (EOOL terminates; NOP is a lone byte;
// every other option's length octet counts the whole option). The locate/iterate primitives (struct_view,
// tlv_cursor) are NANOTINS_HD; the table growth (std::vector::push_back) is host-only, and the bulk path
// (ipv4_children_bulk.hpp) brings the same primitives to the device-callable count -> scatter pipeline.

#include "nanotins/dag_decode.hpp"
#include "nanotins/spec_dag.hpp"
#include "nanotins/tlv.hpp"
#include "nanotins/wire_spec.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>
#include <vector>

namespace nanotins {

using namespace literals;

// ---- child table (SoA, host accumulator) -------------------------------------------------------------

// One row per IPv4 option: which packet, the option's type octet (full type incl. copied/class/number
// bits), and the option's on-wire length in bytes (1 for the single-byte NOP/EOOL markers; the option's
// self-inclusive length octet for every other option).
struct ipv4_opt_table {
    std::vector<std::uint64_t> packet_id;
    std::vector<std::uint8_t> opt_type;
    std::vector<std::uint8_t> opt_len;  // on-wire option length in bytes
    std::size_t size() const { return packet_id.size(); }
    void add(std::uint64_t pid, std::uint8_t type, std::uint8_t len) {
        packet_id.push_back(pid);
        opt_type.push_back(type);
        opt_len.push_back(len);
    }
};

struct ipv4_child_tables {
    ipv4_opt_table opt;
};

// ---- the single shared traversal (NANOTINS_HD): the ONE source of truth for serial emit, the bulk count
//      pass, and the bulk scatter pass — so the three can never disagree (serial == bulk == future gpu) ----

// Visit each option of the IPv4 header at offset `off`: on_opt(type, on_wire_len). The option region is
// [off + 20, off + IHL*4); a too-small IHL (< 5) means no options. All variable reads are clamped to the
// real packet end, so a truncated / over-claiming header yields a partial-but-bounded visit (never OOB).
// Device-safe.
template <class OnOpt>
NANOTINS_HD inline void for_each_ipv4_opt(const std::uint8_t* pkt, std::size_t off, std::size_t size,
                                          OnOpt on_opt) noexcept {
    const std::uint8_t* p = pkt + off;
    const std::size_t hdr_len = static_cast<std::size_t>(struct_view<Ipv4Spec>(p)("ihl"_fld)) * 4u;
    if (hdr_len <= 20) {
        return;  // no option space (or a malformed IHL < 5)
    }
    const std::size_t end_off = (off + hdr_len <= size) ? (off + hdr_len) : size;  // clamp to packet
    const std::uint8_t* end = pkt + end_off;
    const std::uint8_t* start = p + 20;  // after the fixed IPv4 header
    if (start >= end) {
        return;
    }
    tlv_cursor c{start, end, tlv_pad::ipv4_options};
    tlv_record r{};
    while (c.next(r)) {
        // r.length is the value (data) length; the on-wire option length is that + the 2-byte type/len
        // preamble, except the single-byte NOP/EOOL markers (value == nullptr) which occupy exactly 1 byte.
        const std::uint8_t on_wire = (r.value == nullptr) ? std::uint8_t{1}
                                                          : static_cast<std::uint8_t>(r.length + 2);
        on_opt(r.type, on_wire);
    }
}

// ---- serial emission (host): the for_each callback pushes into the child table -----------------------
inline void emit_ipv4_opt_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off,
                                   std::size_t size, ipv4_child_tables& kids) {
    for_each_ipv4_opt(pkt, off, size,
                      [&](std::uint8_t type, std::uint8_t len) { kids.opt.add(pid, type, len); });
}

// ---- bulk primitives (NANOTINS_HD): count + POD sink + scatter, mirroring dag_bulk / ipv6_children ----

// Per-packet child counts (count pass output); addable for the exclusive prefix-sum.
struct ipv4_child_counts {
    std::uint32_t opt = 0;
    NANOTINS_HD ipv4_child_counts operator+(const ipv4_child_counts& o) const noexcept {
        return {opt + o.opt};
    }
};

// Count a packet's option rows by re-walking the graph and the same for_each traversal the scatter uses, so
// count == scattered rows exactly. No writes; device-safe.
template <class Graph>
NANOTINS_HD inline ipv4_child_counts count_packet_ipv4_children(int root, const std::uint8_t* p,
                                                                std::size_t size) noexcept {
    ipv4_child_counts c{};
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv4Node>) {
            for_each_ipv4_opt(p, off, size, [&](std::uint8_t, std::uint8_t) { ++c.opt; });
        }
    });
    return c;
}

// POD sink: raw column pointers into the (pre-sized) child table. Trivially copyable -> a GPU kernel can
// capture it by value.
struct ipv4_child_sink {
    std::uint64_t* opt_pid;
    std::uint8_t* opt_type;
    std::uint8_t* opt_len;
};

// Re-walk a packet and write each option row to base + its own emit order (the exclusive-scan slot). Every
// index derives solely from this packet's base + emit order, so packets never collide: identical output
// serially, on a CPU pool, or (later) on the GPU. Device-safe.
template <class Graph>
NANOTINS_HD inline void scatter_packet_ipv4_children(std::uint64_t pid, int root, const std::uint8_t* p,
                                                     std::size_t size, ipv4_child_counts base,
                                                     const ipv4_child_sink& sink) noexcept {
    std::uint32_t opt = base.opt;
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv4Node>) {
            for_each_ipv4_opt(p, off, size, [&](std::uint8_t type, std::uint8_t len) {
                sink.opt_pid[opt] = pid;
                sink.opt_type[opt] = type;
                sink.opt_len[opt] = len;
                ++opt;
            });
        }
    });
}

static_assert(std::is_trivially_copyable_v<ipv4_child_sink>, "ipv4_child_sink must be POD for GPU capture");
static_assert(std::is_trivially_copyable_v<ipv4_child_counts>, "ipv4_child_counts must be POD");

// Decode one packet's fixed per-node tables AND its IPv4 option child records in a single walk (lockstep
// with the DAG). The fixed-row append is identical to dag_decode_packet; the child emission fires only for
// the Ipv4Node (compile-time dispatch, so other graphs are unaffected).
template <class Graph>
void dag_decode_packet_with_ipv4_children(std::uint64_t packet_id, const std::uint8_t* pkt, std::size_t size,
                                          dag_tables<Graph>& tabs, ipv4_child_tables& kids, int root = 0) {
    walk<Graph>(root, pkt, size, [&](auto Ic, std::size_t off) {
        constexpr std::size_t I = decltype(Ic)::value;
        std::get<I>(tabs).append(packet_id, pkt + off);  // the fixed per-node row (== dag_decode_packet)
        using N = std::tuple_element_t<I, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, Ipv4Node>) {
            emit_ipv4_opt_children(packet_id, pkt, off, size, kids);
        }
    });
}

}  // namespace nanotins
