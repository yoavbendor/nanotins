// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// DPAR — Dynamic Parser Application Rules. A host-side, TCAM-style *trigger layer* on top of the
// device-safe walk<Graph> (spec_dag.hpp). A rule says, in CLI/config terms:
//
//   "when this packet's header fields match these conditions, run an already-implemented parser over
//    this payload region and tabulate the result."
//
//   e.g.  udp.src_port == 0 && udp.dst_port == 9999  =>  someip_tlv  udp_payload  "XYZtlv"
//
// The DAG stays pure/heuristic-free (architecture.html's "reject heuristics" rule): all the config-aware
// "this region is TLV / SOME/IP" knowledge lives HERE, above the walk, never inside it.
//
// This header is the MATCHING ENGINE only and is dependency-light (wire_spec + spec_dag + the cursors;
// no boost, no SoA, no Arrow), so it compiles in the zero-dependency smoke tier. The user-extensible
// *parser palette* — the closed, compile-time set of parsers a rule may activate, plus their SoA output
// tables — is a thin layer on top in dpar_palette.hpp (which pulls in soatins reflection). The split
// keeps the matcher testable standalone and lets a downstream project add its own parser type.
//
// Opt-in / zero-overhead when unused: nothing in the core walk references DPAR. dpar_match() early-returns
// on an empty ruleset, so a tool that wires DPAR but is given no rules does exactly one branch per packet
// and builds no catalog/tables.

#include "nanotins/spec_dag.hpp"
#include "nanotins/wire_spec.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace nanotins::dpar {

// ---- comparators + region kinds ----------------------------------------------------------------------
enum class CmpOp : std::uint8_t { eq, lt, gt, le, ge };  // `ne` is intentionally parked (express as 2 rules)

// The payload region a matched rule hands to its parser. The anchor is the framing node the region is
// measured from; it must have been emitted by the walk for the region to resolve. `eth_payload` is the
// L2 payload (after the 14-byte Ethernet II header); `vlan_payload` is the payload after an 802.1Q tag
// (the 4 bytes after the VLAN node) — both entry points for a link-layer protocol such as LLDP that
// rides directly on Ethernet (untagged or VLAN-tagged) rather than over IP/L4.
enum class RegionKind : std::uint8_t { eth_payload, vlan_payload, udp_payload, tcp_payload, someip_payload };

// ---- a resolved field location (POD) -----------------------------------------------------------------
// Built at init from the compile-time WireSpec field list; read at runtime by read_field_runtime. Mirrors
// read_field (wire_spec.hpp) exactly for scalar and bit-fields (byte-array fields are not predicate
// targets and are excluded from the catalog).
struct FieldRef {
    std::uint16_t node_id = 0;    // index of the framing node in the graph
    std::uint16_t offset = 0;     // byte offset of the field WITHIN the node header
    std::uint8_t byte_width = 0;  // bytes to read (scalar size, or the bit-field's storage unit width)
    std::uint8_t big_endian = 0;  // 1 = big-endian wire order
    std::uint8_t is_bitfield = 0;
    std::uint8_t bit_offset = 0;  // MSB-first bit offset within the storage unit (big-endian convention)
    std::uint8_t bit_width = 0;
};

struct Predicate {
    FieldRef field;
    CmpOp op = CmpOp::eq;
    std::uint64_t operand = 0;
};

struct RegionSel {
    RegionKind kind = RegionKind::udp_payload;
    std::uint16_t anchor_node_id = 0;
};

inline constexpr std::size_t kMaxPredicates = 6;
inline constexpr std::size_t kRuleNameLen = 32;

struct Rule {
    Predicate preds[kMaxPredicates]{};
    std::uint8_t n_preds = 0;
    std::uint16_t parser_kind = 0;  // index into the palette (resolved from a name at init)
    RegionSel region{};
    std::uint32_t rule_id = 0;
    std::uint16_t priority = 0;
    char name[kRuleNameLen] = {};  // observability label (NOT an output column)
};

// ---- the runtime field reader (non-templated mirror of read_field) -----------------------------------
NANOTINS_HD inline std::uint64_t read_field_runtime(const std::uint8_t* base, const FieldRef& f) noexcept {
    std::uint64_t v = 0;
    const std::size_t n = f.byte_width;
    if (f.big_endian) {
        for (std::size_t i = 0; i < n; ++i) {
            v = (v << 8) | static_cast<std::uint64_t>(base[f.offset + i]);
        }
    } else {
        for (std::size_t i = n; i-- > 0;) {
            v = (v << 8) | static_cast<std::uint64_t>(base[f.offset + i]);
        }
    }
    if (!f.is_bitfield) {
        return v;
    }
    const std::uint64_t mask = (f.bit_width >= 64) ? ~std::uint64_t{0} : ((std::uint64_t{1} << f.bit_width) - 1);
    std::size_t shift = f.bit_offset;
    if (f.big_endian) {
        shift = static_cast<std::size_t>(f.byte_width) * 8u - f.bit_width - f.bit_offset;
    }
    return (v >> shift) & mask;
}

// ---- the field catalog: every scalar/bit-field of every node, by (node, field) name ------------------
struct CatalogEntry {
    const char* node;   // framing node name (e.g. "udp"); static storage
    const char* field;  // field name (e.g. "dst_port"); static storage (Tag::value)
    FieldRef ref;
};

namespace detail {

// Resolve a single WireSpec field type F to a FieldRef. Returns false for byte-array fields (addresses /
// blobs) — they are not scalar predicate targets and are omitted from the catalog.
template <class F>
bool field_to_ref(FieldRef& out) {
    if constexpr (requires { F::byte_count; }) {
        return false;
    } else if constexpr (requires { F::bit_offset; F::width; F::storage_bits; }) {
        out.offset = static_cast<std::uint16_t>(F::offset);
        out.byte_width = static_cast<std::uint8_t>(F::storage_bits / 8u);
        out.big_endian = (F::order == wire_endian::big) ? 1u : 0u;
        out.is_bitfield = 1u;
        out.bit_offset = static_cast<std::uint8_t>(F::bit_offset);
        out.bit_width = static_cast<std::uint8_t>(F::width);
        return true;
    } else {
        out.offset = static_cast<std::uint16_t>(F::offset);
        out.byte_width = static_cast<std::uint8_t>(sizeof(typename F::value_type));
        out.big_endian = (F::order == wire_endian::big) ? 1u : 0u;
        out.is_bitfield = 0u;
        return true;
    }
}

template <class Graph, std::size_t I>
void add_node_catalog(std::vector<CatalogEntry>& out, const char* const* names) {
    using N = std::tuple_element_t<I, typename Graph::nodes>;
    using Fields = spec_fields_t<typename N::spec>;
    [&]<std::size_t... J>(std::index_sequence<J...>) {
        ([&] {
            using F = std::tuple_element_t<J, Fields>;
            FieldRef ref{};
            ref.node_id = static_cast<std::uint16_t>(I);
            if (field_to_ref<F>(ref)) {
                out.push_back(CatalogEntry{names[I], F::name(), ref});
            }
        }(),
         ...);
    }(std::make_index_sequence<std::tuple_size_v<Fields>>{});
}

}  // namespace detail

// Build the catalog for a graph given a parallel array of node names (names[i] is the name of node id i).
template <class Graph>
std::vector<CatalogEntry> build_field_catalog(const char* const* names) {
    std::vector<CatalogEntry> out;
    [&]<std::size_t... I>(std::index_sequence<I...>) {
        (detail::add_node_catalog<Graph, I>(out, names), ...);
    }(std::make_index_sequence<Graph::size>{});
    return out;
}

// Node-name table parallel to L2L3Graph (spec_dag.hpp). DPAR-local so the DAG stays untouched; the
// static_assert guards it against drifting out of sync with the graph.
inline constexpr const char* kL2L3NodeNames[] = {
    "eth",          "vlan",         "ipv4",          "ipv6",         "tcp",
    "udp",          "gptp",         "ptp_timestamp", "ptp_ts_port",  "ptp_announce",
    "ptp_signaling","ipv6_hbh",     "ipv6_routing",  "ipv6_fragment","ipv6_destopt",
    "ipv6_ah",      "someip"};
static_assert(sizeof(kL2L3NodeNames) / sizeof(kL2L3NodeNames[0]) == L2L3Graph::size,
              "kL2L3NodeNames must stay parallel to L2L3Graph");

inline std::vector<CatalogEntry> build_l2l3_catalog() {
    return build_field_catalog<L2L3Graph>(kL2L3NodeNames);
}

// Look up a (node, field) pair in the catalog; nullptr if absent.
inline const CatalogEntry* find_field(const std::vector<CatalogEntry>& cat, const char* node,
                                      const char* field) {
    for (const CatalogEntry& e : cat) {
        if (std::strcmp(e.node, node) == 0 && std::strcmp(e.field, field) == 0) {
            return &e;
        }
    }
    return nullptr;
}

// ---- observability ------------------------------------------------------------------------------------
struct RuleStat {
    std::uint64_t matched = 0;       // packets where this rule's predicates all passed
    std::uint64_t rows_emitted = 0;  // output rows this rule produced
};

struct EngineStats {
    std::uint64_t packets_seen = 0;
    std::uint64_t packets_matched_any = 0;
    std::uint64_t rules_evaluated = 0;
    std::uint64_t rows_emitted = 0;
    std::vector<RuleStat> per_rule;  // indexed by rule_id
};

// ---- init-time rule compilation + validation ---------------------------------------------------------
struct CompileResult {
    bool ok = false;
    std::vector<Rule> rules;
    std::vector<std::string> errors;  // one human-readable message per problem found (all collected)
};

namespace detail {

inline std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> t;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
            ++i;
        }
        std::size_t j = i;
        while (j < line.size() && line[j] != ' ' && line[j] != '\t' && line[j] != '\r') {
            ++j;
        }
        if (j > i) {
            t.push_back(line.substr(i, j - i));
        }
        i = j;
    }
    return t;
}

inline bool parse_op(const std::string& s, CmpOp& op) {
    if (s == "==") { op = CmpOp::eq; return true; }
    if (s == "<") { op = CmpOp::lt; return true; }
    if (s == ">") { op = CmpOp::gt; return true; }
    if (s == "<=") { op = CmpOp::le; return true; }
    if (s == ">=") { op = CmpOp::ge; return true; }
    return false;
}

inline bool parse_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty()) {
        return false;
    }
    char* endp = nullptr;
    out = std::strtoull(s.c_str(), &endp, 0);  // base 0: decimal, or 0x.. hex
    return endp != nullptr && *endp == '\0';
}

inline bool parse_region(const std::string& s, RegionKind& kind, const char*& anchor_name) {
    if (s == "eth_payload") { kind = RegionKind::eth_payload; anchor_name = "eth"; return true; }
    if (s == "vlan_payload") { kind = RegionKind::vlan_payload; anchor_name = "vlan"; return true; }
    if (s == "udp_payload") { kind = RegionKind::udp_payload; anchor_name = "udp"; return true; }
    if (s == "tcp_payload") { kind = RegionKind::tcp_payload; anchor_name = "tcp"; return true; }
    if (s == "someip_payload") { kind = RegionKind::someip_payload; anchor_name = "someip"; return true; }
    return false;
}

inline int anchor_node_id(const std::vector<CatalogEntry>& cat, const char* node) {
    for (const CatalogEntry& e : cat) {
        if (std::strcmp(e.node, node) == 0) {
            return static_cast<int>(e.ref.node_id);
        }
    }
    return -1;
}

inline std::string strip_quotes(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

}  // namespace detail

// Compile a rules text into validated Rules. Grammar (one rule per non-blank, non-`#` line):
//
//   <node>.<field> <op> <value> [ && <node>.<field> <op> <value> ]*  =>  <parser>  <region>  "<label>"
//
//   <op>      one of ==  <  >  <=  >=
//   <value>   decimal or 0x-hex; must fit the field's width
//   <parser>  a name in `parser_names` (the palette's Kind names)
//   <region>  eth_payload | vlan_payload | udp_payload | tcp_payload | someip_payload
//
// Every problem is collected (not just the first); on any error, ok=false and `rules` is empty.
inline CompileResult compile_rules(const std::string& text, const std::vector<CatalogEntry>& catalog,
                                   const std::vector<std::string>& parser_names) {
    using namespace detail;
    CompileResult res;
    std::vector<Rule> rules;
    std::uint32_t line_no = 0;
    std::uint32_t ordinal = 0;

    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
        ++line_no;

        std::vector<std::string> tok = tokenize(line);
        if (tok.empty() || tok[0][0] == '#') {
            continue;
        }

        auto err = [&](const std::string& m) {
            res.errors.push_back("rule line " + std::to_string(line_no) + ": " + m);
        };

        Rule rule{};
        rule.rule_id = ordinal;
        rule.priority = static_cast<std::uint16_t>(ordinal);
        ++ordinal;
        bool rule_ok = true;

        std::size_t i = 0;
        // ---- predicates ----
        while (true) {
            if (i + 2 >= tok.size()) {
                err("expected '<node>.<field> <op> <value>'");
                rule_ok = false;
                break;
            }
            const std::string& lhs = tok[i];
            const std::string& ops = tok[i + 1];
            const std::string& vals = tok[i + 2];
            i += 3;

            std::size_t dot = lhs.find('.');
            if (dot == std::string::npos) {
                err("predicate '" + lhs + "' must be <node>.<field>");
                rule_ok = false;
            }
            CmpOp op{};
            if (!parse_op(ops, op)) {
                err("unknown comparator '" + ops + "' (use == < > <= >=)");
                rule_ok = false;
            }
            std::uint64_t operand = 0;
            if (!parse_u64(vals, operand)) {
                err("operand '" + vals + "' is not an integer");
                rule_ok = false;
            }
            if (dot != std::string::npos) {
                std::string node = lhs.substr(0, dot);
                std::string field = lhs.substr(dot + 1);
                const CatalogEntry* ce = find_field(catalog, node.c_str(), field.c_str());
                if (ce == nullptr) {
                    err("unknown field '" + lhs + "'");
                    rule_ok = false;
                } else {
                    const std::size_t bits =
                        ce->ref.is_bitfield ? ce->ref.bit_width : static_cast<std::size_t>(ce->ref.byte_width) * 8u;
                    if (bits < 64 && operand >= (std::uint64_t{1} << bits)) {
                        err("operand " + vals + " overflows " + lhs + " (" + std::to_string(bits) + " bits)");
                        rule_ok = false;
                    }
                    if (rule.n_preds >= kMaxPredicates) {
                        err("too many predicates (max " + std::to_string(kMaxPredicates) + ")");
                        rule_ok = false;
                    } else {
                        rule.preds[rule.n_preds++] = Predicate{ce->ref, op, operand};
                    }
                }
            }

            if (i < tok.size() && tok[i] == "&&") {
                ++i;
                continue;
            }
            break;
        }

        // ---- => parser region "label" ----
        if (i >= tok.size() || tok[i] != "=>") {
            err("expected '=>' after predicates");
            rule_ok = false;
        } else {
            ++i;
            if (i >= tok.size()) {
                err("expected a parser name after '=>'");
                rule_ok = false;
            } else {
                const std::string parser = tok[i++];
                std::uint16_t kind = 0;
                bool found = false;
                for (std::size_t k = 0; k < parser_names.size(); ++k) {
                    if (parser_names[k] == parser) {
                        kind = static_cast<std::uint16_t>(k);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    std::string avail;
                    for (const std::string& n : parser_names) {
                        avail += (avail.empty() ? "" : ", ") + n;
                    }
                    err("unknown parser '" + parser + "' (available: " + avail + ")");
                    rule_ok = false;
                }
                rule.parser_kind = kind;
            }

            if (i >= tok.size()) {
                err("expected a region after the parser");
                rule_ok = false;
            } else {
                RegionKind rk{};
                const char* anchor = nullptr;
                if (!parse_region(tok[i], rk, anchor)) {
                    err("unknown region '" + tok[i] + "' (udp_payload | tcp_payload | someip_payload)");
                    rule_ok = false;
                } else {
                    int aid = anchor_node_id(catalog, anchor);
                    if (aid < 0) {
                        err("region anchor node '" + std::string(anchor) + "' is not in the graph");
                        rule_ok = false;
                    } else {
                        rule.region = RegionSel{rk, static_cast<std::uint16_t>(aid)};
                    }
                }
                ++i;
            }

            // optional label (defaults to the parser name's table)
            if (i < tok.size()) {
                std::string label = strip_quotes(tok[i]);
                std::strncpy(rule.name, label.c_str(), kRuleNameLen - 1);
            }
        }

        if (rule_ok) {
            rules.push_back(rule);
        }
    }

    if (res.errors.empty()) {
        res.ok = true;
        res.rules = std::move(rules);
    }
    return res;
}

// ---- the per-packet matcher --------------------------------------------------------------------------
NANOTINS_HD inline bool cmp_apply(std::uint64_t v, CmpOp op, std::uint64_t o) noexcept {
    switch (op) {
        case CmpOp::eq: return v == o;
        case CmpOp::lt: return v < o;
        case CmpOp::gt: return v > o;
        case CmpOp::le: return v <= o;
        case CmpOp::ge: return v >= o;
    }
    return false;
}

// Resolve a rule's region to [out_begin, out_end) using the walk's per-node offsets. Returns false if the
// anchor framing node was not seen, or the region starts past the captured bytes. Always clamps to `size`.
template <class Graph>
inline bool resolve_region(const RegionSel& rs, const std::size_t* off_by_node, const bool* present,
                           const std::uint8_t* pkt, std::size_t size, const std::uint8_t*& out_begin,
                           const std::uint8_t*& out_end) {
    const int a = rs.anchor_node_id;
    if (a < 0 || !present[a]) {
        return false;
    }
    const std::size_t aoff = off_by_node[a];
    std::size_t begin = size;
    std::size_t end = size;
    switch (rs.kind) {
        case RegionKind::eth_payload:
            begin = aoff + 14u;  // fixed Ethernet II header (an untagged frame; a rule matching
                                 // eth.ethertype is only true when there is no VLAN tag, so this is
                                 // exactly the L2 payload start — e.g. an LLDP frame on EtherType 0x88CC)
            break;
        case RegionKind::vlan_payload:
            begin = aoff + 4u;  // the 4-byte 802.1Q tag after the VLAN node (a rule matching
                                // vlan.inner_ethertype implies a single tag, so this is the tagged
                                // frame's L2 payload start — e.g. LLDP on a trunk port)
            break;
        case RegionKind::udp_payload:
            begin = aoff + 8u;  // fixed UDP header
            break;
        case RegionKind::tcp_payload: {
            const std::size_t hdr =
                static_cast<std::size_t>(struct_view<TcpSpec>(pkt + aoff)("data_offset"_fld)) * 4u;
            begin = aoff + (hdr >= 20 ? hdr : 20);
            break;
        }
        case RegionKind::someip_payload: {
            begin = aoff + kSomeipHeaderLen;
            const std::size_t total =
                aoff + 8u + static_cast<std::size_t>(struct_view<SomeipSpec>(pkt + aoff)("length"_fld));
            if (total < end) {
                end = total;
            }
            break;
        }
    }
    if (begin > size) {
        return false;
    }
    if (end < begin) {
        end = begin;
    }
    out_begin = pkt + begin;
    out_end = pkt + end;
    return true;
}

// Evaluate every rule against one packet (all-match: each rule whose predicates pass fires, in rule order).
// `on_match(kind, pid, rule_id, region_begin, region_end) -> rows` runs the selected parser and returns the
// number of rows it emitted. Strictly opt-in: returns immediately on an empty ruleset.
template <class Graph, class OnMatch>
void dpar_match(const std::vector<Rule>& rules, const std::uint8_t* pkt, std::size_t size,
                std::uint64_t pid, EngineStats& stats, OnMatch&& on_match) {
    if (rules.empty()) {
        return;
    }
    if (stats.per_rule.size() < rules.size()) {
        stats.per_rule.resize(rules.size());
    }

    std::size_t off_by_node[Graph::size] = {};
    bool present[Graph::size] = {};
    walk<Graph>(kEthRoot, pkt, size, [&](auto Ic, std::size_t off) {
        constexpr std::size_t idx = decltype(Ic)::value;
        off_by_node[idx] = off;
        present[idx] = true;
    });
    ++stats.packets_seen;

    bool any = false;
    for (const Rule& rule : rules) {
        ++stats.rules_evaluated;
        bool ok = true;
        for (std::uint8_t k = 0; k < rule.n_preds; ++k) {
            const Predicate& pr = rule.preds[k];
            if (!present[pr.field.node_id]) {  // a missing layer makes the predicate false (present-bit safety)
                ok = false;
                break;
            }
            const std::uint64_t v = read_field_runtime(pkt + off_by_node[pr.field.node_id], pr.field);
            if (!cmp_apply(v, pr.op, pr.operand)) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        const std::uint8_t* rb = nullptr;
        const std::uint8_t* re = nullptr;
        if (!resolve_region<Graph>(rule.region, off_by_node, present, pkt, size, rb, re)) {
            continue;
        }
        const std::size_t rows = on_match(rule.parser_kind, pid, rule.rule_id, rb, re);
        RuleStat& rstat = stats.per_rule[rule.rule_id];
        ++rstat.matched;
        rstat.rows_emitted += rows;
        stats.rows_emitted += rows;
        any = true;
    }
    if (any) {
        ++stats.packets_matched_any;
    }
}

}  // namespace nanotins::dpar
