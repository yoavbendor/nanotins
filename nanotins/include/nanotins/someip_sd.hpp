// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// SOME/IP-SD (Service Discovery) variable-length child records: the entries array and the options array of
// an SD message. A single SD message carries 0..N entries and 0..M options, so — exactly like the IPv6/IPv4
// option tables — they do NOT fit "one row per DAG node" and go into their own child tables keyed by
// packet_id. SD is self-describing on the wire (entries are a fixed 16-byte stride; options are 2-byte
// length-prefixed), so it is decodable here with no IDL — this is the repeat_at / tlv_cursor pattern
// (tlv.hpp) applied to the SD payload that hangs off a SomeipNode.
//
// The SD payload only exists when the SOME/IP message is the SD message (Message ID 0xFFFF8100); the walk
// confirms that from the header before descending. The locate/iterate primitives (struct_view, read_field,
// the inline option cursor) are NANOTINS_HD; the table growth (std::vector::push_back) is host-only, and the
// bulk count -> scatter primitives below bring the same single traversal to the device-callable path
// (serial == bulk == future gpu, the invariant the IPv6/IPv4 child tables also hold).

#include "nanotins/dag_decode.hpp"
#include "nanotins/spec_dag.hpp"
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

// One row per SD entry: which packet, the entry's order within the message, and the decoded entry fields.
// `minor_version` is the raw trailing 32-bit word — a Minor Version for service entries, or packed
// reserved+counter+eventgroup-id for eventgroup entries (reinterpret by `type`).
struct someip_sd_entry_table {
    std::vector<std::uint64_t> packet_id;
    std::vector<std::uint8_t> entry_index;
    std::vector<std::uint8_t> type;
    std::vector<std::uint8_t> index_1st_opts;
    std::vector<std::uint8_t> index_2nd_opts;
    std::vector<std::uint8_t> num_opt_1;
    std::vector<std::uint8_t> num_opt_2;
    std::vector<std::uint16_t> service_id;
    std::vector<std::uint16_t> instance_id;
    std::vector<std::uint8_t> major_version;
    std::vector<std::uint32_t> ttl;
    std::vector<std::uint32_t> minor_version;
    std::size_t size() const { return packet_id.size(); }
    void add(std::uint64_t pid, std::uint8_t idx, const std::uint8_t* e) {
        struct_view<SomeipSdEntrySpec> v(e);
        packet_id.push_back(pid);
        entry_index.push_back(idx);
        type.push_back(v("type"_fld));
        index_1st_opts.push_back(v("index_1st_opts"_fld));
        index_2nd_opts.push_back(v("index_2nd_opts"_fld));
        num_opt_1.push_back(v("num_opt_1"_fld));
        num_opt_2.push_back(v("num_opt_2"_fld));
        service_id.push_back(v("service_id"_fld));
        instance_id.push_back(v("instance_id"_fld));
        major_version.push_back(v("major_version"_fld));
        ttl.push_back(v("ttl"_fld));
        minor_version.push_back(v("minor_version"_fld));
    }
};

// One row per SD option: which packet, the option's order, its on-wire Length field + Type octet, and — for
// the endpoint options (IPv4/IPv6, uni/multicast/SD) — the decoded endpoint (L4 protocol, port, and the
// address as fixed_size_binary(16): IPv4 in the first 4 bytes, IPv6 the full 16, zero for non-endpoints).
struct someip_sd_option_table {
    std::vector<std::uint64_t> packet_id;
    std::vector<std::uint8_t> option_index;
    std::vector<std::uint16_t> length;
    std::vector<std::uint8_t> type;
    std::vector<std::uint8_t> l4proto;
    std::vector<std::uint16_t> port;
    std::vector<std::array<std::uint8_t, 16>> address;
    std::size_t size() const { return packet_id.size(); }
    void add(std::uint64_t pid, std::uint8_t idx, std::uint16_t len, std::uint8_t ty, std::uint8_t l4,
             std::uint16_t pt, const std::array<std::uint8_t, 16>& addr) {
        packet_id.push_back(pid);
        option_index.push_back(idx);
        length.push_back(len);
        type.push_back(ty);
        l4proto.push_back(l4);
        port.push_back(pt);
        address.push_back(addr);
    }
};

struct someip_sd_child_tables {
    someip_sd_entry_table entry;
    someip_sd_option_table option;
};

// ---- endpoint-option decode (NANOTINS_HD) ------------------------------------------------------------
// Decode the address/L4-proto/port of an endpoint option into out-params; returns true if `type` is an
// endpoint option (so the caller knows the fields are meaningful). Option bytes: [len:2][type:1][res:1] then
// IPv4: addr(4) res(1) proto(1) port(2); IPv6: addr(16) res(1) proto(1) port(2). Every read is bounded by
// `end` — a truncated option leaves the unread fields zero rather than reading out of bounds.
NANOTINS_HD inline bool sd_decode_endpoint(const std::uint8_t* opt, std::uint8_t type, const std::uint8_t* end,
                                           std::uint8_t addr[16], std::uint8_t& l4proto,
                                           std::uint16_t& port) noexcept {
    for (int i = 0; i < 16; ++i) {
        addr[i] = 0;
    }
    l4proto = 0;
    port = 0;
    const bool v4 = (type == kSdOptIpv4Endpoint || type == kSdOptIpv4Multicast || type == kSdOptIpv4SdEndpoint);
    const bool v6 = (type == kSdOptIpv6Endpoint || type == kSdOptIpv6Multicast || type == kSdOptIpv6SdEndpoint);
    if (!v4 && !v6) {
        return false;
    }
    const std::size_t addr_n = v4 ? 4u : 16u;
    const std::uint8_t* a = opt + 4;             // after [len:2][type:1][reserved:1]
    const std::uint8_t* proto = a + addr_n + 1;  // skip address + 1 reserved byte
    const std::uint8_t* prt = proto + 1;
    if (prt + 2 > end) {
        return true;  // endpoint type, but truncated -> fields stay zero (bounded)
    }
    for (std::size_t i = 0; i < addr_n; ++i) {
        addr[i] = a[i];
    }
    l4proto = proto[0];
    port = read_scalar_at<std::uint16_t, wire_endian::big>(prt, 0);
    return true;
}

// ---- the single shared traversal (NANOTINS_HD): the ONE source of truth for serial emit, the bulk count
//      pass, and the bulk scatter pass — so the three can never disagree ----
//
// Visit each child of the SD message whose SOME/IP header is at offset `off`: on_entry(entry_index, ptr) for
// every 16-byte entry, then on_option(option_index, ptr, length, type) for every option. Does nothing if the
// SOME/IP message is not SD. All variable reads are clamped to the real packet end (and to the SD region's
// own length fields), so a truncated / over-claiming SD message yields a partial-but-bounded visit.
template <class OnEntry, class OnOption>
NANOTINS_HD inline void for_each_sd_child(const std::uint8_t* pkt, std::size_t off, std::size_t size,
                                          OnEntry on_entry, OnOption on_option) noexcept {
    const std::uint8_t* h = pkt + off;
    if (off + kSomeipHeaderLen > size) {
        return;
    }
    struct_view<SomeipSpec> sv(h);
    if (sv("service_id"_fld) != kSomeipSdServiceId || sv("method_id"_fld) != kSomeipSdMethodId) {
        return;  // a normal SOME/IP message, not SD
    }
    // SD region end: the SOME/IP length covers from byte 8 to end of payload (= off + 8 + length), clamped
    // to the captured packet.
    const std::size_t msg_end_off = off + 8u + static_cast<std::size_t>(sv("length"_fld));
    const std::size_t end_off = (msg_end_off <= size) ? msg_end_off : size;
    const std::uint8_t* end = pkt + end_off;

    const std::uint8_t* sd = h + kSomeipHeaderLen;  // SD payload start
    if (sd + kSomeipSdPreambleLen > end) {
        return;
    }
    // Entries array: [flags:1][res:3][entries_length:4] then the entries.
    const std::uint32_t entries_len = struct_view<SomeipSdHeaderSpec>(sd)("entries_length"_fld);
    const std::uint8_t* entries = sd + kSomeipSdPreambleLen;
    const std::uint8_t* entries_end = entries + entries_len;
    if (entries_end > end) {
        entries_end = end;  // clamp an over-claiming entries_length
    }
    const std::uint32_t n_entries = static_cast<std::uint32_t>((entries_end - entries) / kSomeipSdEntrySize);
    for (std::uint32_t i = 0; i < n_entries; ++i) {
        on_entry(static_cast<std::uint8_t>(i), entries + std::size_t{i} * kSomeipSdEntrySize);
    }

    // Options array: a 4-byte options_length word at the (declared) end of the entries array, then options.
    const std::uint8_t* opt_len_at = entries + entries_len;  // declared entries end (not the clamp)
    if (opt_len_at + 4 > end) {
        return;
    }
    const std::uint32_t options_len = read_scalar_at<std::uint32_t, wire_endian::big>(opt_len_at, 0);
    const std::uint8_t* opt = opt_len_at + 4;
    const std::uint8_t* opt_end = opt + options_len;
    if (opt_end > end) {
        opt_end = end;  // clamp an over-claiming options_length
    }
    std::uint32_t oi = 0;
    while (opt + 3 <= opt_end) {  // need [length:2][type:1]
        const std::uint16_t len = read_scalar_at<std::uint16_t, wire_endian::big>(opt, 0);
        const std::uint8_t type = opt[2];
        const std::uint8_t* next = opt + 3u + len;  // Length counts the bytes after the type octet
        if (next > opt_end) {
            break;  // truncated / over-claiming option -> stop (bounded)
        }
        on_option(static_cast<std::uint8_t>(oi), opt, len, type);
        ++oi;
        opt = next;
    }
}

// ---- serial emission (host): the for_each callbacks push into the child tables -----------------------
inline void emit_sd_children(std::uint64_t pid, const std::uint8_t* pkt, std::size_t off, std::size_t size,
                             const std::uint8_t* end, someip_sd_child_tables& kids) {
    for_each_sd_child(
        pkt, off, size,
        [&](std::uint8_t idx, const std::uint8_t* e) { kids.entry.add(pid, idx, e); },
        [&](std::uint8_t idx, const std::uint8_t* o, std::uint16_t len, std::uint8_t type) {
            std::uint8_t addr[16];
            std::uint8_t l4 = 0;
            std::uint16_t port = 0;
            sd_decode_endpoint(o, type, end, addr, l4, port);
            std::array<std::uint8_t, 16> a{};
            std::memcpy(a.data(), addr, 16);
            kids.option.add(pid, idx, len, type, l4, port, a);
        });
}

// ---- bulk primitives (NANOTINS_HD): count + POD sink + scatter, mirroring ipv4_children / ipv6_children -

// Per-packet child counts (count pass output); addable for the exclusive prefix-sum.
struct someip_sd_child_counts {
    std::uint32_t entry = 0;
    std::uint32_t option = 0;
    NANOTINS_HD someip_sd_child_counts operator+(const someip_sd_child_counts& o) const noexcept {
        return {entry + o.entry, option + o.option};
    }
};

// Count a packet's SD child rows by re-walking the graph and the same traversal the scatter uses, so count
// == scattered rows exactly. No writes; device-safe.
template <class Graph>
NANOTINS_HD inline someip_sd_child_counts count_packet_someip_sd_children(int root, const std::uint8_t* p,
                                                                          std::size_t size) noexcept {
    someip_sd_child_counts c{};
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, SomeipNode>) {
            for_each_sd_child(
                p, off, size, [&](std::uint8_t, const std::uint8_t*) { ++c.entry; },
                [&](std::uint8_t, const std::uint8_t*, std::uint16_t, std::uint8_t) { ++c.option; });
        }
    });
    return c;
}

// POD sink: raw column pointers into the (pre-sized) child tables. opt_addr is a flat 16-bytes-per-row
// buffer. Trivially copyable -> a GPU kernel can capture it by value.
struct someip_sd_child_sink {
    std::uint64_t* entry_pid;
    std::uint8_t* entry_index;
    std::uint8_t* entry_type;
    std::uint8_t* entry_index_1st;
    std::uint8_t* entry_index_2nd;
    std::uint8_t* entry_num_opt_1;
    std::uint8_t* entry_num_opt_2;
    std::uint16_t* entry_service_id;
    std::uint16_t* entry_instance_id;
    std::uint8_t* entry_major_version;
    std::uint32_t* entry_ttl;
    std::uint32_t* entry_minor_version;
    std::uint64_t* opt_pid;
    std::uint8_t* opt_index;
    std::uint16_t* opt_length;
    std::uint8_t* opt_type;
    std::uint8_t* opt_l4proto;
    std::uint16_t* opt_port;
    std::uint8_t* opt_addr;  // row i at opt_addr + i*16
};

// Re-walk a packet and write each SD child row to base + its own emit order (the exclusive-scan slot). Every
// index derives solely from this packet's base + emit order, so packets never collide: identical output
// serially, on a CPU pool, or (later) on the GPU. Device-safe.
template <class Graph>
NANOTINS_HD inline void scatter_packet_someip_sd_children(std::uint64_t pid, int root, const std::uint8_t* p,
                                                          std::size_t size, someip_sd_child_counts base,
                                                          const someip_sd_child_sink& sink) noexcept {
    std::uint32_t ei = base.entry;
    std::uint32_t oi = base.option;
    walk<Graph>(root, p, size, [&](auto Ic, std::size_t off) {
        using N = std::tuple_element_t<decltype(Ic)::value, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, SomeipNode>) {
            const std::uint8_t* end = p + size;
            for_each_sd_child(
                p, off, size,
                [&](std::uint8_t idx, const std::uint8_t* e) {
                    struct_view<SomeipSdEntrySpec> v(e);
                    sink.entry_pid[ei] = pid;
                    sink.entry_index[ei] = idx;
                    sink.entry_type[ei] = v("type"_fld);
                    sink.entry_index_1st[ei] = v("index_1st_opts"_fld);
                    sink.entry_index_2nd[ei] = v("index_2nd_opts"_fld);
                    sink.entry_num_opt_1[ei] = v("num_opt_1"_fld);
                    sink.entry_num_opt_2[ei] = v("num_opt_2"_fld);
                    sink.entry_service_id[ei] = v("service_id"_fld);
                    sink.entry_instance_id[ei] = v("instance_id"_fld);
                    sink.entry_major_version[ei] = v("major_version"_fld);
                    sink.entry_ttl[ei] = v("ttl"_fld);
                    sink.entry_minor_version[ei] = v("minor_version"_fld);
                    ++ei;
                },
                [&](std::uint8_t idx, const std::uint8_t* o, std::uint16_t len, std::uint8_t type) {
                    std::uint8_t addr[16];
                    std::uint8_t l4 = 0;
                    std::uint16_t port = 0;
                    sd_decode_endpoint(o, type, end, addr, l4, port);
                    sink.opt_pid[oi] = pid;
                    sink.opt_index[oi] = idx;
                    sink.opt_length[oi] = len;
                    sink.opt_type[oi] = type;
                    sink.opt_l4proto[oi] = l4;
                    sink.opt_port[oi] = port;
                    for (int i = 0; i < 16; ++i) {
                        sink.opt_addr[std::size_t{oi} * 16u + i] = addr[i];
                    }
                    ++oi;
                });
        }
    });
}

static_assert(std::is_trivially_copyable_v<someip_sd_child_sink>, "sink must be POD for GPU capture");
static_assert(std::is_trivially_copyable_v<someip_sd_child_counts>, "counts must be POD");

// Decode one packet's fixed per-node tables AND its SOME/IP-SD child records in a single walk (lockstep with
// the DAG). The fixed-row append is identical to dag_decode_packet; the SD child emission fires only for a
// SomeipNode carrying an SD message (compile-time node dispatch + the runtime SD-message check inside
// for_each_sd_child), so other graphs / non-SD SOME/IP messages are unaffected.
template <class Graph>
void dag_decode_packet_with_someip_sd(std::uint64_t packet_id, const std::uint8_t* pkt, std::size_t size,
                                      dag_tables<Graph>& tabs, someip_sd_child_tables& kids, int root = 0) {
    const std::uint8_t* end = pkt + size;
    walk<Graph>(root, pkt, size, [&](auto Ic, std::size_t off) {
        constexpr std::size_t I = decltype(Ic)::value;
        std::get<I>(tabs).append(packet_id, pkt + off);  // the fixed per-node row (== dag_decode_packet)
        using N = std::tuple_element_t<I, typename Graph::nodes>;
        if constexpr (std::is_same_v<N, SomeipNode>) {
            emit_sd_children(packet_id, pkt, off, size, end, kids);
        }
    });
}

}  // namespace nanotins
