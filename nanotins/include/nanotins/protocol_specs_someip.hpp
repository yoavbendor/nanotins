// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// SOME/IP (Scalable service-Oriented MiddlewarE over IP, AUTOSAR PRS_SOMEIP) as a wire_spec — the
// automotive RPC/event transport that rides on UDP/TCP alongside gPTP. This Phase-1 header covers the
// fixed 16-byte SOME/IP message header, which is all fixed-offset big-endian fields and therefore a clean
// fit for the wire_spec machinery (exactly like UdpSpec):
//
//   [ Service ID:2 | Method ID:2 ]  <- Message ID (4)
//   [ Length:4 ]                     covers Request ID .. end of payload (so payload = length - 8)
//   [ Client ID:2 | Session ID:2 ]  <- Request ID (4)
//   [ Proto Ver:1 | Iface Ver:1 | Msg Type:1 | Return Code:1 ]
//
// The variable payload that follows is NOT decoded here: standard SOME/IP serialization is flat and only
// interpretable with the interface/IDL model, while SOME/IP-SD (Service Discovery) and the optional TLV
// serialization are self-describing enough for their own later phases (SD entries/options child tables;
// a someip_tlv_cursor sibling of tlv.hpp). The DAG node's advance() therefore consumes only the 16-byte
// header; the payload boundary is recoverable as header offset + (length + 8).

#include "nanotins/wire_spec.hpp"

#include <cstdint>

namespace nanotins {

using namespace literals;

// ---- the fixed 16-byte SOME/IP message header --------------------------------------------------------
// Message ID and Request ID are exposed as their semantic halves (service/method, client/session) — the
// natural columns for service-oriented analysis — rather than as opaque 32-bit words.
using SomeipSpec = WireSpec<
    named_field<decltype("service_id"_fld), 0, std::uint16_t, wire_endian::big>,
    named_field<decltype("method_id"_fld), 2, std::uint16_t, wire_endian::big>,
    named_field<decltype("length"_fld), 4, std::uint32_t, wire_endian::big>,
    named_field<decltype("client_id"_fld), 8, std::uint16_t, wire_endian::big>,
    named_field<decltype("session_id"_fld), 10, std::uint16_t, wire_endian::big>,
    named_field<decltype("protocol_version"_fld), 12, std::uint8_t, wire_endian::big>,
    named_field<decltype("interface_version"_fld), 13, std::uint8_t, wire_endian::big>,
    named_field<decltype("message_type"_fld), 14, std::uint8_t, wire_endian::big>,
    named_field<decltype("return_code"_fld), 15, std::uint8_t, wire_endian::big>>;

// Fixed header size (bytes). The `length` field counts from byte 8 onward, so the wire message spans
// kSomeipHeaderLen + (length - 8) == 8 + length bytes total.
inline constexpr std::size_t kSomeipHeaderLen = 16;

// Well-known SOME/IP Service Discovery UDP/TCP port (AUTOSAR). The DAG dispatches UDP/TCP -> SOME/IP on
// this port; additional service ports are dynamic and added as extra edges by configuration.
inline constexpr std::uint16_t kSomeipSdPort = 30490;

// Service Discovery is itself a SOME/IP message with this reserved Message ID (Service 0xFFFF, Method
// 0x8100) and protocol/interface version 0x01. Used by a later phase to sub-dispatch the SD payload.
inline constexpr std::uint16_t kSomeipSdServiceId = 0xFFFF;
inline constexpr std::uint16_t kSomeipSdMethodId = 0x8100;

// Message Type (byte 14) values. The high bit (0x20, "TP flag") marks a SOME/IP-TP segment whose first
// payload bytes are a TP header; reassembly is a stateful concern above the framing layer.
inline constexpr std::uint8_t kSomeipRequest = 0x00;
inline constexpr std::uint8_t kSomeipRequestNoReturn = 0x01;
inline constexpr std::uint8_t kSomeipNotification = 0x02;
inline constexpr std::uint8_t kSomeipResponse = 0x80;
inline constexpr std::uint8_t kSomeipError = 0x81;
inline constexpr std::uint8_t kSomeipTpFlag = 0x20;

// ---- SOME/IP-SD (Service Discovery) payload specs ----------------------------------------------------
// An SD message is a SOME/IP message (Message ID 0xFFFF8100) whose payload is self-describing — unlike a
// flat-serialized RPC payload, it needs no IDL to walk. Layout (AUTOSAR PRS_SOMEIPServiceDiscovery):
//
//   [ Flags:1 | Reserved:3 ]
//   [ Length of Entries Array:4 ] [ Entries: N x 16-byte entries ]
//   [ Length of Options Array:4 ] [ Options: M variable-length options ]
//
// The 8-byte SD preamble: a flags byte (Reboot 0x80, Unicast 0x40) + 3 reserved, then the entries-array
// byte length. Entries start at SD-payload byte 8; options start after the entries array + its own 4-byte
// length word. These are decoded into child tables (someip_sd.hpp), like the IPv6/IPv4 option tables.
using SomeipSdHeaderSpec = WireSpec<
    named_field<decltype("flags"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("entries_length"_fld), 4, std::uint32_t, wire_endian::big>>;

// A 16-byte SD entry. Service entries (FindService 0x00, OfferService 0x01) carry a 32-bit Minor Version
// in the trailing word; eventgroup entries (Subscribe 0x06, SubscribeAck 0x07) instead pack reserved +
// counter + a 16-bit Eventgroup ID there — exposed as the raw `minor_version` word, which the consumer
// reinterprets by entry type. num_opt_1/num_opt_2 are the two 4-bit option-run counts in byte 3; ttl is the
// 24-bit lifetime in bytes 9..11 (read as the low 24 bits of the big-endian word at byte 8).
using SomeipSdEntrySpec = WireSpec<
    named_field<decltype("type"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("index_1st_opts"_fld), 1, std::uint8_t, wire_endian::big>,
    named_field<decltype("index_2nd_opts"_fld), 2, std::uint8_t, wire_endian::big>,
    named_bit_field<decltype("num_opt_1"_fld), 3, std::uint8_t, 0, 4, wire_endian::big>,
    named_bit_field<decltype("num_opt_2"_fld), 3, std::uint8_t, 4, 4, wire_endian::big>,
    named_field<decltype("service_id"_fld), 4, std::uint16_t, wire_endian::big>,
    named_field<decltype("instance_id"_fld), 6, std::uint16_t, wire_endian::big>,
    named_field<decltype("major_version"_fld), 8, std::uint8_t, wire_endian::big>,
    named_bit_field<decltype("ttl"_fld), 8, std::uint32_t, 8, 24, wire_endian::big>,
    named_field<decltype("minor_version"_fld), 12, std::uint32_t, wire_endian::big>>;

inline constexpr std::size_t kSomeipSdEntrySize = 16;
inline constexpr std::size_t kSomeipSdPreambleLen = 8;  // flags + reserved + entries_length

// SD entry Type octet values.
inline constexpr std::uint8_t kSdEntryFindService = 0x00;
inline constexpr std::uint8_t kSdEntryOfferService = 0x01;
inline constexpr std::uint8_t kSdEntrySubscribeEventgroup = 0x06;
inline constexpr std::uint8_t kSdEntrySubscribeEventgroupAck = 0x07;

// SD Option Type octet values. The endpoint options (IPv4/IPv6, uni/multicast/SD) carry an address +
// L4-protocol + port — the "who offers/finds this service, and where" payload that makes SD useful.
inline constexpr std::uint8_t kSdOptConfiguration = 0x01;
inline constexpr std::uint8_t kSdOptLoadBalancing = 0x02;
inline constexpr std::uint8_t kSdOptIpv4Endpoint = 0x04;
inline constexpr std::uint8_t kSdOptIpv6Endpoint = 0x06;
inline constexpr std::uint8_t kSdOptIpv4Multicast = 0x14;
inline constexpr std::uint8_t kSdOptIpv6Multicast = 0x16;
inline constexpr std::uint8_t kSdOptIpv4SdEndpoint = 0x24;
inline constexpr std::uint8_t kSdOptIpv6SdEndpoint = 0x26;

}  // namespace nanotins
