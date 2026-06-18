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

}  // namespace nanotins
