// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// DPAR Arrow export (nanotins/dpar_arrow.hpp): run the DPAR engine to fill a per-Kind rule table, export
// it to an Arrow record batch, and check the column buffers carry the expected values. The Arrow half of
// the "rule rows -> columnar" path (the Lance write is exercised in nanolance). Covers:
//   A1  table_to_arrow over a someip_tlv rule table: ArrowArray length + child count match the rows
//   A2  the data buffers (packet_id / rule_id / data_id / wire_type / length) hold the right values
//   A3  the discriminator (rule_id) distinguishes rows produced by different rules into one table
//   A4  an empty table yields a valid zero-length batch

#include "nanotins/dpar_arrow.hpp"
#include "nanotins/dpar_palette.hpp"

#include <nanoarrow/nanoarrow.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace dpar = nanotins::dpar;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

void put8(std::vector<std::uint8_t>& b, std::size_t off, std::uint8_t v) { b[off] = v; }
void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v);
}
void put_tag(std::vector<std::uint8_t>& b, std::uint8_t wt, std::uint16_t id) {
    b.push_back(static_cast<std::uint8_t>((wt << 4) | ((id >> 8) & 0x0F)));
    b.push_back(static_cast<std::uint8_t>(id & 0xFF));
}
std::vector<std::uint8_t> build_udp(std::uint16_t src, std::uint16_t dst,
                                    const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> b(42, 0);
    put16(b, 12, 0x0800);
    put8(b, 14, 0x45);
    put8(b, 23, 17);
    put16(b, 34, src);
    put16(b, 36, dst);
    put16(b, 38, static_cast<std::uint16_t>(8 + payload.size()));
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

// The someip_tlv Row column order (from BOOST_DESCRIBE_STRUCT in dpar_palette.hpp):
//   0 packet_id u64, 1 rule_id u32, 2 member_index u32, 3 data_id u16, 4 wire_type u8,
//   5 length u32, 6 value_offset u32
template <class T>
const T* col(const ArrowArray& a, int i) {
    return static_cast<const T*>(a.children[i]->buffers[1]);  // buffer 0 = validity, 1 = data
}

}  // namespace

int main() {
    using G = nanotins::L2L3Graph;

    // ---- A1/A2/A3: a someip_tlv table -> Arrow, two rules sharing the table -------------------------
    {
        dpar::dpar_engine<G, dpar::DefaultPalette> engine;
        CHECK(engine
                  .load_rules(
                      "udp.dst_port == 9999 => someip_tlv udp_payload A\n"
                      "udp.dst_port == 9999 => someip_tlv udp_payload B\n")
                  .ok);

        // two TLV members: 8-bit base (id 0x011, value 0x42), len8 (id 0x022, 1 byte 0x99)
        std::vector<std::uint8_t> payload;
        put_tag(payload, 0, 0x011);
        payload.push_back(0x42);
        put_tag(payload, 5, 0x022);
        payload.push_back(0x01);
        payload.push_back(0x99);

        auto pkt = build_udp(0, 9999, payload);
        engine.run(pkt.data(), pkt.size(), /*pid=*/5);

        const auto& rows = std::get<0>(engine.palette.tables);  // SomeipTlvRow table
        CHECK(rows.size() == 4);                                 // 2 members x 2 rules

        ArrowArray batch{};
        std::string err;
        CHECK(dpar::table_to_arrow(rows, batch, err));
        CHECK(err.empty());
        CHECK(batch.length == 4);
        CHECK(batch.n_children == 7);  // the 7 described columns

        const std::uint64_t* packet_id = col<std::uint64_t>(batch, 0);
        const std::uint32_t* rule_id = col<std::uint32_t>(batch, 1);
        const std::uint32_t* member_index = col<std::uint32_t>(batch, 2);
        const std::uint16_t* data_id = col<std::uint16_t>(batch, 3);
        const std::uint8_t* wire_type = col<std::uint8_t>(batch, 4);
        const std::uint32_t* length = col<std::uint32_t>(batch, 5);

        for (int i = 0; i < 4; ++i) {
            CHECK(packet_id[i] == 5);
        }
        // rows 0,1 from rule 0; rows 2,3 from rule 1 (deterministic rule order) — the discriminator.
        CHECK(rule_id[0] == 0 && rule_id[1] == 0 && rule_id[2] == 1 && rule_id[3] == 1);
        CHECK(data_id[0] == 0x011 && data_id[1] == 0x022 && data_id[2] == 0x011 && data_id[3] == 0x022);
        CHECK(wire_type[0] == 0 && wire_type[1] == 5);
        CHECK(member_index[0] == 0 && member_index[1] == 1 && member_index[2] == 0 && member_index[3] == 1);
        CHECK(length[0] == 1 && length[1] == 1);

        batch.release(&batch);

        // The standalone schema names the columns (sanity: 7 children, first is packet_id).
        ArrowSchema schema{};
        CHECK(dpar::table_schema<dpar::SomeipTlvRow>(schema, err));
        CHECK(schema.n_children == 7);
        CHECK(std::string(schema.children[0]->name) == "packet_id");
        CHECK(std::string(schema.children[1]->name) == "rule_id");
        schema.release(&schema);
    }

    // ---- A4: an empty table yields a valid zero-length batch ----------------------------------------
    {
        std::vector<dpar::RawTlvRow> empty;
        ArrowArray batch{};
        std::string err;
        CHECK(dpar::table_to_arrow(empty, batch, err));
        CHECK(batch.length == 0);
        CHECK(batch.n_children == 5);  // RawTlvRow: packet_id, rule_id, index, type, length
        batch.release(&batch);
    }

    std::printf("dpar_arrow: ok (table->arrow length+children, column buffers, rule_id discriminator, empty table)\n");
    return 0;
}
