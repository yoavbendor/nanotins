// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// =====================================================================================================
// LLDP — a worked example of ADDING YOUR OWN PROTOCOL PARSER and applying it with DPAR.
// =====================================================================================================
//
// This header is a tutorial. It shows, end to end and from a *library user's* point of view, how to:
//
//   1. write a small bounded parser for a real protocol (LLDP), using only the lib's primitives;
//   2. describe its output rows so they become a columnar SoA table "for free" (struct -> SoA -> Arrow);
//   3. wrap the parser as a DPAR "Kind" and drop it into a parser_palette — no fork of nanotins;
//   4. drive it from a CLI rule that says *when* to apply it.
//
// LLDP (Link Layer Discovery Protocol, IEEE 802.1AB) is what switches use to advertise their identity to
// neighbours. It is a good teaching target: it rides DIRECTLY ON ETHERNET (EtherType 0x88CC — no IP, no
// UDP), and its payload is a flat list of TLVs with a packed 7-bit-type / 9-bit-length header. So it
// exercises a different layer (L2) than everything else in the tree, and it is "simple but not trivial".
//
// Why DPAR (and not a DAG node)? An LLDP frame has no fixed header to tabulate — it is *all* variable
// TLVs — and we want to apply it selectively by rule. DPAR is exactly that: a rule matches header fields
// (here `eth.ethertype == 0x88CC`) and hands our parser the matched payload region. The framing DAG in
// spec_dag.hpp stays untouched.
//
// Everything a user writes here lives OUTSIDE the nanotins include tree — this is application code.

#include "nanotins/dpar_palette.hpp"  // parser_palette, dpar_engine, CompileResult, EngineStats

#include "soatins/describe.hpp"   // nt_field_count / nt_names (used by helpers, if you want reflection)
#include "soatins/portability.hpp"  // NANOTINS_HD — your parser can be host- AND device-callable too

#include <boost/describe.hpp>  // BOOST_DESCRIBE_STRUCT — marks a row struct so soatins reflects its columns

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace lldp_example {

// ---- 1. LLDP wire vocabulary -------------------------------------------------------------------------
// LLDP rides on Ethernet under this EtherType. A DPAR rule matches it to decide a frame is LLDP.
inline constexpr std::uint16_t kLldpEtherType = 0x88CC;

// TLV type codes (the high 7 bits of each TLV's 2-byte header). The first three are mandatory and must
// appear in order; the End TLV closes the LLDPDU; the rest are optional.
inline constexpr std::uint16_t kLldpEnd = 0;          // End of LLDPDU (length 0) — terminates the walk
inline constexpr std::uint16_t kLldpChassisId = 1;    // value = [subtype:1][chassis id ...]
inline constexpr std::uint16_t kLldpPortId = 2;       // value = [subtype:1][port id ...]
inline constexpr std::uint16_t kLldpTtl = 3;          // value = [ttl:2] (seconds the info stays valid)
inline constexpr std::uint16_t kLldpPortDesc = 4;     // value = port description string
inline constexpr std::uint16_t kLldpSysName = 5;      // value = system (host) name string
inline constexpr std::uint16_t kLldpSysDesc = 6;      // value = system description string
inline constexpr std::uint16_t kLldpSysCaps = 7;      // value = [capabilities:2][enabled:2]
inline constexpr std::uint16_t kLldpMgmtAddr = 8;     // value = management address (length-prefixed)
inline constexpr std::uint16_t kLldpOrgSpecific = 127;  // value = [OUI:3][subtype:1][info ...]

// A human-readable name for a TLV type (used by the NDJSON dumper; purely cosmetic).
inline const char* lldp_type_name(std::uint16_t t) {
    switch (t) {
        case kLldpEnd: return "end";
        case kLldpChassisId: return "chassis_id";
        case kLldpPortId: return "port_id";
        case kLldpTtl: return "ttl";
        case kLldpPortDesc: return "port_desc";
        case kLldpSysName: return "system_name";
        case kLldpSysDesc: return "system_desc";
        case kLldpSysCaps: return "system_caps";
        case kLldpMgmtAddr: return "mgmt_address";
        case kLldpOrgSpecific: return "org_specific";
        default: return "unknown";
    }
}

// ---- 2. the parser: a bounded, allocation-free TLV cursor --------------------------------------------
// Modelled on the lib's someip_tlv_cursor (someip_tlv.hpp): trivially copyable, NANOTINS_HD, every read
// bounded by `end`. The only LLDP-specific part is the packed header: 16 bits = [type:7][length:9].
struct lldp_tlv_record {
    std::uint16_t type;         // 0..127
    std::uint16_t length;       // 0..511 (9 bits) — the value length in bytes
    const std::uint8_t* value;  // -> `length` bytes inside the payload (nullptr when length == 0)
};

struct lldp_cursor {
    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;

    // Decode the next TLV into `out`. Returns false at the End TLV (type 0), at end-of-region, or on a
    // record that would run past `end` — so it can never read out of bounds, even on a malformed frame.
    NANOTINS_HD bool next(lldp_tlv_record& out) noexcept {
        if (p == nullptr || p + 2 > end) {  // need the 2-byte type/length header
            return false;
        }
        const std::uint16_t hdr = static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
        const std::uint16_t type = static_cast<std::uint16_t>(hdr >> 9);       // top 7 bits
        const std::uint16_t length = static_cast<std::uint16_t>(hdr & 0x01FF);  // bottom 9 bits
        if (type == kLldpEnd) {
            return false;  // End of LLDPDU — stop (trailing pad / FCS, if any, is ignored)
        }
        const std::uint8_t* v = p + 2;
        if (v + length > end) {
            return false;  // value would overrun the region
        }
        out = lldp_tlv_record{type, length, length == 0 ? nullptr : v};
        p = v + length;
        return true;
    }
};

// ---- 3. the output row: describe it once, get a columnar SoA/Arrow table for free --------------------
// One row per TLV. Note the data model: variable-length strings (a system name, a chassis id) CANNOT be
// SoA columns (soatins columns are scalars, be<>/le<>, or fixed-size byte arrays). So, exactly like the
// built-in SomeipTlvRow, we store the value's byte OFFSET + LENGTH, plus a fixed-size `value_head`
// snapshot (a std::array<uint8,N> maps to an Arrow fixed-size-binary column) that captures the first 32
// value bytes — enough to actually SEE the system name / port id in the output, not just its position.
//
// On top of that, the structured TLVs (TTL, System Capabilities, Management Address) are DECODED into
// typed columns. Those columns are 0 for TLVs that do not use them — the same sparse-but-uniform shape
// the SOME/IP-SD entry table uses, where one row type carries fields several entry kinds reinterpret.
struct LldpTlvRow {
    std::uint64_t packet_id;             // which packet (the capture-order id)
    std::uint32_t rule_id;               // which rule emitted this row (the discriminator)
    std::uint32_t tlv_index;             // 0-based position of this TLV within the frame
    std::uint16_t tlv_type;              // LLDP TLV type (see lldp_type_name)
    std::uint16_t tlv_length;            // value length in bytes (0..511)
    std::uint8_t subtype;                // chassis/port-id subtype (value[0] for types 1/2; else 0)
    std::uint16_t value_offset;          // offset of the value bytes from the region (payload) start
    // --- decoded, type-specific columns (0 when the TLV type does not carry them) ---
    std::uint16_t ttl_seconds;           // type 3 (TTL): seconds the neighbour info stays valid
    std::uint16_t caps_supported;        // type 7 (System Capabilities): capability bitmap
    std::uint16_t caps_enabled;          // type 7 (System Capabilities): which of the above are enabled
    std::uint8_t mgmt_addr_subtype;      // type 8: IANA address family (1=IPv4, 2=IPv6, 6=802 MAC, ...)
    std::uint8_t mgmt_iface_subtype;     // type 8: interface numbering subtype (2=ifIndex, 3=sysPortNum)
    std::uint32_t mgmt_iface_number;     // type 8: the interface number
    std::array<std::uint8_t, 32> value_head;  // first up-to-32 value bytes, zero-padded (fixed-binary col)
};
BOOST_DESCRIBE_STRUCT(LldpTlvRow, (),
                      (packet_id, rule_id, tlv_index, tlv_type, tlv_length, subtype, value_offset,
                       ttl_seconds, caps_supported, caps_enabled, mgmt_addr_subtype, mgmt_iface_subtype,
                       mgmt_iface_number, value_head))

// Tiny big-endian reads from a value byte buffer. The caller guards the offset against the TLV length
// first, so these never run past the (already bounded) value region.
inline std::uint16_t rd_be16(const std::uint8_t* v) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(v[0]) << 8) | v[1]);
}
inline std::uint32_t rd_be32(const std::uint8_t* v) {
    return (static_cast<std::uint32_t>(v[0]) << 24) | (static_cast<std::uint32_t>(v[1]) << 16) |
           (static_cast<std::uint32_t>(v[2]) << 8) | static_cast<std::uint32_t>(v[3]);
}

// ---- 4. the DPAR Kind: wrap the parser so a rule can select it -------------------------------------
// A Kind is the extension point. It is just: a Row type, a name() (the CLI selector + table label), and
// an emit() that runs the parser over the region the rule handed us and pushes one Row per TLV. That is
// the entire contract — compose this into a parser_palette and it is a first-class parser.
struct LldpKind {
    using Row = LldpTlvRow;
    static constexpr const char* name() { return "lldp"; }

    static std::size_t emit(std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                            const std::uint8_t* end, std::vector<Row>& out) {
        lldp_cursor c{p, end};
        lldp_tlv_record r{};
        std::uint32_t idx = 0;
        std::size_t n = 0;
        while (c.next(r)) {
            Row row{};
            row.packet_id = pid;
            row.rule_id = rule_id;
            row.tlv_index = idx;
            row.tlv_type = r.type;
            row.tlv_length = r.length;
            // Chassis ID (1) and Port ID (2) prepend a 1-byte subtype to their value; surface it.
            row.subtype = ((r.type == kLldpChassisId || r.type == kLldpPortId) && r.length >= 1 && r.value)
                              ? r.value[0]
                              : 0;
            row.value_offset = static_cast<std::uint16_t>(r.value != nullptr ? r.value - p : 0);
            // Snapshot up to 32 value bytes so the actual content is visible downstream.
            const std::size_t head = r.length < row.value_head.size() ? r.length : row.value_head.size();
            for (std::size_t i = 0; i < head; ++i) {
                row.value_head[i] = r.value[i];
            }
            // Decode the structured TLVs into typed columns. Each read is guarded against r.length, so a
            // truncated/malformed TLV simply leaves the column at 0 (never reads past the value region).
            decode_typed(r, row);
            out.push_back(row);
            ++idx;
            ++n;
        }
        return n;
    }

private:
    static void decode_typed(const lldp_tlv_record& r, Row& row) {
        const std::uint8_t* v = r.value;
        if (v == nullptr) {
            return;
        }
        switch (r.type) {
            case kLldpTtl:  // [ttl:2] — seconds the advertised info remains valid
                if (r.length >= 2) {
                    row.ttl_seconds = rd_be16(v);
                }
                break;
            case kLldpSysCaps:  // [capabilities:2][enabled:2] — two IEEE 802.1AB capability bitmaps
                if (r.length >= 4) {
                    row.caps_supported = rd_be16(v);
                    row.caps_enabled = rd_be16(v + 2);
                }
                break;
            case kLldpMgmtAddr: {
                // [addr_str_len:1][addr_subtype:1][addr:addr_str_len-1][iface_subtype:1][iface_num:4][oid..]
                // addr_str_len counts the subtype byte + the address bytes.
                if (r.length < 1) {
                    break;
                }
                const std::size_t addr_str_len = v[0];
                if (addr_str_len < 1 || r.length < 1u + addr_str_len) {
                    break;
                }
                row.mgmt_addr_subtype = v[1];                  // IANA address family
                const std::size_t after_addr = 1u + addr_str_len;  // index of the interface-subtype byte
                if (r.length >= after_addr + 1u) {
                    row.mgmt_iface_subtype = v[after_addr];
                }
                if (r.length >= after_addr + 1u + 4u) {
                    row.mgmt_iface_number = rd_be32(v + after_addr + 1u);
                }
                break;
            }
            default:
                break;
        }
    }
};

// ---- 5. the palette: this binary's closed set of parsers (here, just LLDP) --------------------------
// A downstream tool composes the palette it wants. We only need LLDP, but you could list more Kinds.
using LldpPalette = nanotins::dpar::parser_palette<LldpKind>;

// ---- 6. a small NDJSON dumper (hand-written so we can render the LLDP fields nicely) ----------------
// The dpar example used a generic scalar-only reflection dumper; here we write it by hand because we
// want to render `value_head` as hex + printable-ASCII (the reflection dumper only handles scalars).
inline void append_value_head(std::string& out, const LldpTlvRow& r) {
    const std::size_t n = r.tlv_length < r.value_head.size() ? r.tlv_length : r.value_head.size();
    out += "\"hex\":\"";
    for (std::size_t i = 0; i < n; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", r.value_head[i]);
        out += buf;
    }
    out += "\",\"ascii\":\"";
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t b = r.value_head[i];
        // Escape-free preview: render only printable ASCII, and exclude " and \ (which would otherwise
        // need JSON escaping) so the line stays valid NDJSON without an escaper.
        const bool printable = b >= 0x20 && b < 0x7F && b != '"' && b != '\\';
        out += printable ? static_cast<char>(b) : '.';
    }
    out += "\"";
}

// IEEE 802.1AB system-capability bit names (bit 0 = LSB). Render a JSON array of the bits set in `bits`.
inline void append_caps(std::string& out, const char* key, std::uint16_t bits) {
    static const char* kNames[] = {"Other",     "Repeater",  "Bridge",     "WLAN-AP",
                                   "Router",    "Telephone", "DOCSIS",     "Station",
                                   "C-VLAN",    "S-VLAN",    "TPMR"};
    out += "\"";
    out += key;
    out += "\":[";
    bool first = true;
    for (int i = 0; i < 11; ++i) {
        if (bits & (1u << i)) {
            if (!first) {
                out += ",";
            }
            out += "\"";
            out += kNames[i];
            out += "\"";
            first = false;
        }
    }
    out += "]";
}

// Per-type decoded fields (each fragment ends with a comma so the value_head fields can follow). Emits
// nothing for TLV types without a typed decode.
inline void append_decoded(std::string& out, const LldpTlvRow& r) {
    char buf[96];
    switch (r.tlv_type) {
        case kLldpTtl:
            std::snprintf(buf, sizeof(buf), "\"ttl_seconds\":%u,", r.ttl_seconds);
            out += buf;
            break;
        case kLldpSysCaps:
            std::snprintf(buf, sizeof(buf), "\"caps_supported\":%u,\"caps_enabled\":%u,",
                          r.caps_supported, r.caps_enabled);
            out += buf;
            append_caps(out, "caps", r.caps_enabled);  // human-readable enabled list
            out += ",";
            break;
        case kLldpMgmtAddr:
            std::snprintf(buf, sizeof(buf),
                          "\"mgmt_addr_subtype\":%u,\"mgmt_iface_subtype\":%u,\"mgmt_iface_number\":%u,",
                          r.mgmt_addr_subtype, r.mgmt_iface_subtype, r.mgmt_iface_number);
            out += buf;
            break;
        default:
            break;
    }
}

inline void row_to_json(std::string& out, const LldpTlvRow& r) {
    char buf[64];
    out += "{";
    std::snprintf(buf, sizeof(buf), "\"packet_id\":%llu,", static_cast<unsigned long long>(r.packet_id));
    out += buf;
    std::snprintf(buf, sizeof(buf), "\"rule_id\":%u,", r.rule_id);
    out += buf;
    std::snprintf(buf, sizeof(buf), "\"tlv_index\":%u,", r.tlv_index);
    out += buf;
    std::snprintf(buf, sizeof(buf), "\"type\":%u,", r.tlv_type);
    out += buf;
    out += "\"type_name\":\"";
    out += lldp_type_name(r.tlv_type);
    out += "\",";
    std::snprintf(buf, sizeof(buf), "\"length\":%u,", r.tlv_length);
    out += buf;
    std::snprintf(buf, sizeof(buf), "\"subtype\":%u,", r.subtype);
    out += buf;
    std::snprintf(buf, sizeof(buf), "\"value_offset\":%u,", r.value_offset);
    out += buf;
    append_decoded(out, r);     // type-specific decoded fields (ttl/caps/mgmt), if any
    append_value_head(out, r);  // "hex":"..","ascii":".."
    out += "}";
}

// ---- 7. the engine wrapper: load rules, run packets, dump the table ---------------------------------
// Thin convenience around dpar_engine<L2L3Graph, LldpPalette>. Identical shape to the dpar example's
// Engine; only the palette + dumper differ.
class Engine {
public:
    nanotins::dpar::CompileResult load_rules(const std::string& text) { return engine_.load_rules(text); }
    void run(const std::uint8_t* pkt, std::size_t size, std::uint64_t pid) { engine_.run(pkt, size, pid); }
    std::size_t rule_count() const { return engine_.rule_count(); }
    nanotins::dpar::EngineStats& stats() { return engine_.stats; }
    const std::vector<LldpTlvRow>& table() const { return std::get<0>(engine_.palette.tables); }

    // One NDJSON line per emitted TLV row: {"table":"lldp","row":{...}}.
    void dump_ndjson(std::string& out) {
        for (const LldpTlvRow& row : table()) {
            out += "{\"table\":\"lldp\",\"row\":";
            row_to_json(out, row);
            out += "}\n";
        }
    }

private:
    nanotins::dpar::dpar_engine<nanotins::L2L3Graph, LldpPalette> engine_;
};

}  // namespace lldp_example
