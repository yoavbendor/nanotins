// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// The L2/L3/L4 backbone as wire_spec wire specs — the single home for the Ethernet / VLAN / IPv4 / IPv6 /
// TCP / UDP layouts, replacing the be<>/bits<> packed structs in protocols.hpp for the spec-driven decode.
// Field names + types match the described protocols:: structs exactly (verified by test_protocol_specs vs
// the be<>/bits<> overlay), so the per-PDU Lance tables a wire_spec DAG emits are byte-identical to the
// current walk_packet tables. One spec drives host read + device read + SoA + Arrow (see wire_spec.hpp).

#include "nanotins/wire_spec.hpp"

#include <cstdint>

namespace nanotins {

using namespace literals;

// ---- Ethernet II (14 bytes) ----
using EthernetSpec = WireSpec<
    named_bytes_field<decltype("dst"_fld), 0, 6>,
    named_bytes_field<decltype("src"_fld), 6, 6>,
    named_field<decltype("ethertype"_fld), 12, std::uint16_t, wire_endian::big>>;

// ---- 802.1Q VLAN tag (4 bytes: TCI + inner ethertype) ----
using VlanTagSpec = WireSpec<
    named_bit_field<decltype("pcp"_fld), 0, std::uint16_t, 0, 3, wire_endian::big>,
    named_bit_field<decltype("dei"_fld), 0, std::uint16_t, 3, 1, wire_endian::big>,
    named_bit_field<decltype("vid"_fld), 0, std::uint16_t, 4, 12, wire_endian::big>,
    named_field<decltype("inner_ethertype"_fld), 2, std::uint16_t, wire_endian::big>>;

// ---- IPv4 (20-byte fixed header; ihl gives the true length) ----
using Ipv4Spec = WireSpec<
    named_bit_field<decltype("version"_fld), 0, std::uint8_t, 0, 4, wire_endian::big>,
    named_bit_field<decltype("ihl"_fld), 0, std::uint8_t, 4, 4, wire_endian::big>,
    named_bit_field<decltype("dscp"_fld), 1, std::uint8_t, 0, 6, wire_endian::big>,
    named_bit_field<decltype("ecn"_fld), 1, std::uint8_t, 6, 2, wire_endian::big>,
    named_field<decltype("total_length"_fld), 2, std::uint16_t, wire_endian::big>,
    named_field<decltype("identification"_fld), 4, std::uint16_t, wire_endian::big>,
    named_bit_field<decltype("flags"_fld), 6, std::uint16_t, 0, 3, wire_endian::big>,
    named_bit_field<decltype("frag_offset"_fld), 6, std::uint16_t, 3, 13, wire_endian::big>,
    named_field<decltype("ttl"_fld), 8, std::uint8_t, wire_endian::big>,
    named_field<decltype("protocol"_fld), 9, std::uint8_t, wire_endian::big>,
    named_field<decltype("checksum"_fld), 10, std::uint16_t, wire_endian::big>,
    named_bytes_field<decltype("src"_fld), 12, 4>,
    named_bytes_field<decltype("dst"_fld), 16, 4>>;

// ---- IPv6 (40-byte fixed header) ----
using Ipv6Spec = WireSpec<
    named_bit_field<decltype("version"_fld), 0, std::uint32_t, 0, 4, wire_endian::big>,
    named_bit_field<decltype("traffic_class"_fld), 0, std::uint32_t, 4, 8, wire_endian::big>,
    named_bit_field<decltype("flow_label"_fld), 0, std::uint32_t, 12, 20, wire_endian::big>,
    named_field<decltype("payload_length"_fld), 4, std::uint16_t, wire_endian::big>,
    named_field<decltype("next_header"_fld), 6, std::uint8_t, wire_endian::big>,
    named_field<decltype("hop_limit"_fld), 7, std::uint8_t, wire_endian::big>,
    named_bytes_field<decltype("src"_fld), 8, 16>,
    named_bytes_field<decltype("dst"_fld), 24, 16>>;

// ---- TCP (20-byte fixed header) ----
using TcpSpec = WireSpec<
    named_field<decltype("src_port"_fld), 0, std::uint16_t, wire_endian::big>,
    named_field<decltype("dst_port"_fld), 2, std::uint16_t, wire_endian::big>,
    named_field<decltype("seq"_fld), 4, std::uint32_t, wire_endian::big>,
    named_field<decltype("ack"_fld), 8, std::uint32_t, wire_endian::big>,
    named_bit_field<decltype("data_offset"_fld), 12, std::uint16_t, 0, 4, wire_endian::big>,
    named_bit_field<decltype("reserved"_fld), 12, std::uint16_t, 4, 3, wire_endian::big>,
    named_bit_field<decltype("flags"_fld), 12, std::uint16_t, 7, 9, wire_endian::big>,
    named_field<decltype("window"_fld), 14, std::uint16_t, wire_endian::big>,
    named_field<decltype("checksum"_fld), 16, std::uint16_t, wire_endian::big>,
    named_field<decltype("urgent_ptr"_fld), 18, std::uint16_t, wire_endian::big>>;

// ---- UDP (8 bytes) ----
using UdpSpec = WireSpec<
    named_field<decltype("src_port"_fld), 0, std::uint16_t, wire_endian::big>,
    named_field<decltype("dst_port"_fld), 2, std::uint16_t, wire_endian::big>,
    named_field<decltype("length"_fld), 4, std::uint16_t, wire_endian::big>,
    named_field<decltype("checksum"_fld), 6, std::uint16_t, wire_endian::big>>;

// ---- IPv6 extension headers (RFC 8200 §4, RFC 8754 SRv6 SRH) ----------------------------------------
// Every extension header begins with a `next_header` byte that continues the chain (see ip6_next_dispatch
// in spec_dag.hpp). These specs cover each header's FIXED part; the variable parts they carry (SRH segment
// list + TLVs, Hop-by-Hop / Destination options) are walked separately by tlv_cursor / repeat_at and emit
// their own child tables. The DAG node's advance() skips the WHOLE header (incl. the variable part) so the
// chain walk reaches the correct L4 offset.

// Hop-by-Hop Options (next_header 0) and Destination Options (next_header 60) share this 2-byte preamble.
// Header length = (hdr_ext_len + 1) * 8 bytes; the option TLVs fill the remainder.
using Ipv6ExtOptSpec = WireSpec<
    named_field<decltype("next_header"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("hdr_ext_len"_fld), 1, std::uint8_t, wire_endian::big>>;

// Routing header (next_header 43). Routing Type 4 is the SRv6 Segment Routing Header (SRH). Fixed part is
// 8 bytes; followed by (last_entry + 1) 16-byte segments, then optional TLVs. Length = (hdr_ext_len+1)*8.
using Ipv6SrhSpec = WireSpec<
    named_field<decltype("next_header"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("hdr_ext_len"_fld), 1, std::uint8_t, wire_endian::big>,
    named_field<decltype("routing_type"_fld), 2, std::uint8_t, wire_endian::big>,
    named_field<decltype("segments_left"_fld), 3, std::uint8_t, wire_endian::big>,
    named_field<decltype("last_entry"_fld), 4, std::uint8_t, wire_endian::big>,
    named_field<decltype("flags"_fld), 5, std::uint8_t, wire_endian::big>,
    named_field<decltype("tag"_fld), 6, std::uint16_t, wire_endian::big>>;

// Fragment header (next_header 44). Fixed 8 bytes (NOT hdr_ext_len-encoded). Bytes 2-3 pack the fragment
// offset (13 bits), 2 reserved bits, and the More-fragments flag (MSB-first within the big-endian u16).
using Ipv6FragmentSpec = WireSpec<
    named_field<decltype("next_header"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("reserved"_fld), 1, std::uint8_t, wire_endian::big>,
    named_bit_field<decltype("frag_offset"_fld), 2, std::uint16_t, 0, 13, wire_endian::big>,
    named_bit_field<decltype("res2"_fld), 2, std::uint16_t, 13, 2, wire_endian::big>,
    named_bit_field<decltype("more_fragments"_fld), 2, std::uint16_t, 15, 1, wire_endian::big>,
    named_field<decltype("identification"_fld), 4, std::uint32_t, wire_endian::big>>;

// Authentication Header (next_header 51). Length = (payload_len + 2) * 4 bytes (4-byte units). Fixed part
// captured here is 12 bytes; the variable ICV that follows is skipped by advance().
using Ipv6AhSpec = WireSpec<
    named_field<decltype("next_header"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("payload_len"_fld), 1, std::uint8_t, wire_endian::big>,
    named_field<decltype("reserved"_fld), 2, std::uint16_t, wire_endian::big>,
    named_field<decltype("spi"_fld), 4, std::uint32_t, wire_endian::big>,
    named_field<decltype("seq"_fld), 8, std::uint32_t, wire_endian::big>>;

}  // namespace nanotins
