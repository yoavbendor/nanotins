// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// The DPAR parser palette — the closed, compile-time set of parsers a rule may activate, plus their
// columnar output tables. "Closed" means every parser is *compiled code chosen at the final binary's
// build time*, not a hard-coded list inside nanotins and not a runtime-interpreted grammar. The palette
// is therefore user-extensible: a downstream project defines its own parser Kind (built on the lib's TLV
// cursors + the struct->SoA->Arrow reflection) and composes it into parser_palette<...> alongside the
// built-ins — no fork. This mirrors how the framing DAG itself is a graph<Nodes...>.
//
// A parser Kind is a small struct:
//   struct MyKind {
//       using Row = MyRow;                                  // a boost-described struct (its own SoA table)
//       static constexpr const char* name();               // the CLI selector + table label
//       static std::size_t emit(pid, rule_id, p, end, std::vector<Row>& out);  // run over the region, push rows
//   };
//
// Dispatch is an if constexpr chain over the Kinds (no virtuals), so an unused Kind costs nothing and a
// future device-eligible palette can reuse the same compile-time composition. This layer pulls in soatins
// reflection (boost::describe) for the Row -> SoA bridge; the matching engine (dpar.hpp) stays dep-light.

#include "nanotins/dpar.hpp"
#include "nanotins/someip_tlv.hpp"
#include "nanotins/tlv.hpp"

#include "soatins/reflect.hpp"

#include <boost/describe.hpp>

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

namespace nanotins::dpar {

// ---- built-in output rows (described structs => columns + Arrow for free) -----------------------------
// Every row carries packet_id + rule_id (the discriminator that traces a row back to the rule, since one
// table is shared by every rule that selects the same Kind).

struct SomeipTlvRow {
    std::uint64_t packet_id;
    std::uint32_t rule_id;
    std::uint32_t member_index;
    std::uint16_t data_id;
    std::uint8_t wire_type;
    std::uint32_t length;
    std::uint32_t value_offset;  // offset of the value bytes from the region start
};
BOOST_DESCRIBE_STRUCT(SomeipTlvRow, (),
                      (packet_id, rule_id, member_index, data_id, wire_type, length, value_offset))

struct RawTlvRow {
    std::uint64_t packet_id;
    std::uint32_t rule_id;
    std::uint32_t index;
    std::uint8_t type;
    std::uint8_t length;
};
BOOST_DESCRIBE_STRUCT(RawTlvRow, (), (packet_id, rule_id, index, type, length))

// ---- built-in Kinds ----------------------------------------------------------------------------------
// someip_tlv: structural tabulation of SOME/IP-TLV members (data_id / wire_type / length) — no IDL needed.
struct SomeipTlvKind {
    using Row = SomeipTlvRow;
    static constexpr const char* name() { return "someip_tlv"; }
    static std::size_t emit(std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                            const std::uint8_t* end, std::vector<Row>& out) {
        someip_tlv_cursor c{p, end};
        someip_tlv_record r{};
        std::uint32_t idx = 0;
        std::size_t n = 0;
        while (c.next(r)) {
            out.push_back(Row{pid, rule_id, idx, r.data_id, r.wire_type, r.length,
                              static_cast<std::uint32_t>(r.value != nullptr ? r.value - p : 0)});
            ++idx;
            ++n;
        }
        return n;
    }
};

// raw_tlv: generic [type][len][value] records (the tlv.hpp "raw" mode).
struct RawTlvKind {
    using Row = RawTlvRow;
    static constexpr const char* name() { return "raw_tlv"; }
    static std::size_t emit(std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                            const std::uint8_t* end, std::vector<Row>& out) {
        tlv_cursor c{p, end, tlv_pad::raw};
        tlv_record r{};
        std::uint32_t idx = 0;
        std::size_t n = 0;
        while (c.next(r)) {
            out.push_back(Row{pid, rule_id, idx, r.type, r.length});
            ++idx;
            ++n;
        }
        return n;
    }
};

// ---- the palette: a tuple of per-Kind row accumulators + name->index + if constexpr dispatch ----------
template <class... Kinds>
struct parser_palette {
    static constexpr std::size_t size = sizeof...(Kinds);
    using kinds_tuple = std::tuple<Kinds...>;
    template <std::size_t I>
    using kind_at = std::tuple_element_t<I, kinds_tuple>;

    std::tuple<std::vector<typename Kinds::Row>...> tables;

    // The Kind names, in palette order — handed to compile_rules to resolve a rule's parser name.
    static std::vector<std::string> names() { return {Kinds::name()...}; }

    // Run the Kind selected by `kind` over [p, end), appending rows to its table; returns rows emitted.
    std::size_t emit(std::uint16_t kind, std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                     const std::uint8_t* end) {
        return emit_at<0>(kind, pid, rule_id, p, end);
    }

    // Visit each table as f(const char* name, std::vector<Row>&) — for dumping / Arrow export.
    template <class F>
    void for_each_table(F&& f) {
        [&]<std::size_t... I>(std::index_sequence<I...>) {
            (f(kind_at<I>::name(), std::get<I>(tables)), ...);
        }(std::make_index_sequence<size>{});
    }

   private:
    template <std::size_t I>
    std::size_t emit_at(std::uint16_t kind, std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                        const std::uint8_t* end) {
        if constexpr (I < size) {
            if (kind == I) {
                return kind_at<I>::emit(pid, rule_id, p, end, std::get<I>(tables));
            }
            return emit_at<I + 1>(kind, pid, rule_id, p, end);
        } else {
            (void)kind;
            (void)pid;
            (void)rule_id;
            (void)p;
            (void)end;
            return 0;
        }
    }
};

// The default palette = the lib built-ins. A downstream project composes its own, e.g.
//   using MyPalette = parser_palette<SomeipTlvKind, RawTlvKind, MyKind>;
using DefaultPalette = parser_palette<SomeipTlvKind, RawTlvKind>;

// ---- the engine: catalog + rules + palette, driven one packet at a time ------------------------------
template <class Graph, class Palette>
class dpar_engine {
   public:
    Palette palette;
    EngineStats stats;

    explicit dpar_engine(std::vector<CatalogEntry> catalog = build_l2l3_catalog())
        : catalog_(std::move(catalog)) {}

    // Compile rules text against the catalog + the palette's Kind names. On success the rules are loaded
    // and per-rule stats sized; on failure the engine keeps zero rules (and reports the errors).
    CompileResult load_rules(const std::string& text) {
        CompileResult r = compile_rules(text, catalog_, Palette::names());
        if (r.ok) {
            rules_ = r.rules;
            stats.per_rule.assign(rules_.size(), RuleStat{});
        }
        return r;
    }

    std::size_t rule_count() const { return rules_.size(); }
    const std::vector<CatalogEntry>& catalog() const { return catalog_; }

    // Match + emit for one packet. No-op (one branch) when no rules are loaded.
    void run(const std::uint8_t* pkt, std::size_t size, std::uint64_t pid) {
        dpar_match<Graph>(rules_, pkt, size, pid, stats,
                          [&](std::uint16_t kind, std::uint64_t p, std::uint32_t rid, const std::uint8_t* b,
                              const std::uint8_t* e) { return palette.emit(kind, p, rid, b, e); });
    }

   private:
    std::vector<CatalogEntry> catalog_;
    std::vector<Rule> rules_;
};

}  // namespace nanotins::dpar
