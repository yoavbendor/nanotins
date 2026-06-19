// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// The dpar example's reusable core: a DOWNSTREAM parser Kind (OddTlvKind) defined on the lib's TLV cursors
// + struct->SoA->Arrow reflection, the palette that composes it with the built-ins, and a thin Engine that
// loads rules, runs packets, and dumps each table as NDJSON. Kept header-only + free of the pcap/CLI glue
// so it can be unit-tested in-process (test_dpar_example.cpp), exactly like pcapng2json.

#include "nanotins/dpar_palette.hpp"

#include "soatins/describe.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace dpar_example {

namespace ndpar = nanotins::dpar;

// ---- a downstream parser Kind: NOT part of nanotins ---------------------------------------------------
// Tabulates a SOME/IP-TLV "array" member (a len16 descriptor whose value is elem_size/elem_count followed
// by `count` fixed-size elements), parsing each element with the simple TLV cursor. Demonstrates building
// a new parser on the lib primitives and a described Row (so it gets a SoA/Arrow table for free).
struct OddTlvRow {
    std::uint64_t packet_id;
    std::uint32_t rule_id;
    std::uint32_t elem_index;
    std::uint16_t array_id;
    std::uint16_t elem_size;
    std::uint16_t elem_count;
    std::uint16_t elem_data_id;
};
BOOST_DESCRIBE_STRUCT(OddTlvRow, (), (packet_id, rule_id, elem_index, array_id, elem_size, elem_count, elem_data_id))

struct OddTlvKind {
    using Row = OddTlvRow;
    static constexpr const char* name() { return "oddtlv"; }
    static std::size_t emit(std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                            const std::uint8_t* end, std::vector<Row>& out) {
        nanotins::someip_tlv_cursor c{p, end};
        nanotins::someip_tlv_record r{};
        std::size_t n = 0;
        while (c.next(r)) {
            if (r.wire_type == nanotins::kSomeipTlvWtLen16 && r.length >= 4 && r.value != nullptr) {
                const std::uint16_t esz = static_cast<std::uint16_t>((r.value[0] << 8) | r.value[1]);
                const std::uint16_t cnt = static_cast<std::uint16_t>((r.value[2] << 8) | r.value[3]);
                const std::uint8_t* q = r.value + 4;
                for (std::uint16_t i = 0; i < cnt && q + esz <= end; ++i) {
                    nanotins::someip_tlv_cursor ec{q, q + esz};
                    nanotins::someip_tlv_record er{};
                    if (ec.next(er)) {
                        out.push_back(Row{pid, rule_id, i, r.data_id, esz, cnt, er.data_id});
                        ++n;
                    }
                    q += esz;
                }
            }
        }
        return n;
    }
};

// The example's palette = lib built-ins + the downstream Kind. This is the "closed at MY build time" set.
using Palette = ndpar::parser_palette<ndpar::SomeipTlvKind, ndpar::RawTlvKind, OddTlvKind>;

// ---- a generic row -> JSON object over any described Row (scalar columns) ------------------------------
template <class Row>
void row_to_json(std::string& out, const Row& r) {
    out += '{';
    [&]<std::size_t... K>(std::index_sequence<K...>) {
        std::size_t i = 0;
        (((out += (i++ ? "," : ""), out += '"', out += soatins::nt_names<Row>[K], out += "\":",
           out += std::to_string(+(r.*soatins::nt_member_ptr<Row, K>)))),
         ...);
    }(std::make_index_sequence<soatins::nt_field_count<Row>>{});
    out += '}';
}

// ---- the engine wrapper -------------------------------------------------------------------------------
class Engine {
   public:
    ndpar::CompileResult load_rules(const std::string& text) { return engine_.load_rules(text); }
    void run(const std::uint8_t* pkt, std::size_t size, std::uint64_t pid) { engine_.run(pkt, size, pid); }
    std::size_t rule_count() const { return engine_.rule_count(); }
    ndpar::EngineStats& stats() { return engine_.stats; }

    // One NDJSON line per emitted row: {"table":"<kind>", ...row fields...}.
    void dump_ndjson(std::string& out) {
        engine_.palette.for_each_table([&](const char* kind, auto& rows) {
            for (const auto& row : rows) {
                out += "{\"table\":\"";
                out += kind;
                out += "\",\"row\":";
                row_to_json(out, row);
                out += "}\n";
            }
        });
    }

    void dump_stats(std::FILE* f, const std::vector<ndpar::Rule>& rules) {
        const ndpar::EngineStats& s = engine_.stats;
        std::fprintf(f, "dpar stats: packets_seen=%llu matched_any=%llu rules_evaluated=%llu rows=%llu\n",
                     static_cast<unsigned long long>(s.packets_seen),
                     static_cast<unsigned long long>(s.packets_matched_any),
                     static_cast<unsigned long long>(s.rules_evaluated),
                     static_cast<unsigned long long>(s.rows_emitted));
        for (const ndpar::Rule& rule : rules) {
            const ndpar::RuleStat& rs = s.per_rule[rule.rule_id];
            std::fprintf(f, "  rule %u \"%s\": matched=%llu rows=%llu\n", rule.rule_id, rule.name,
                         static_cast<unsigned long long>(rs.matched),
                         static_cast<unsigned long long>(rs.rows_emitted));
        }
    }

   private:
    ndpar::dpar_engine<nanotins::L2L3Graph, Palette> engine_;
};

}  // namespace dpar_example
