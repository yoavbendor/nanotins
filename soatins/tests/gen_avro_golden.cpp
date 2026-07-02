// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Golden-file generator for the avro_glue reflection encoder: writes an .avsc schema + Avro binary-encoded
// row for a fixed test record to the directory given as argv[1]. The companion check_avro_golden.py reads
// both back with fastavro (a real, independent Avro client) and asserts the field values round-trip --
// the cross-check that our no-codegen encoder actually speaks Avro, not just our own reader.

#include "soatins/avro_glue.hpp"
#include "soatins/endian.hpp"
#include "soatins/reflect.hpp"

#include <boost/describe.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

namespace {

struct GoldenRecord {
    soatins::be<std::uint32_t> id;       // wire big-endian u32  -> avro "long"
    soatins::le<std::int64_t> counter;   // wire little-endian i64 -> avro "long"
    float score;                          // host float  -> avro "float"
    double weight;                        // host double -> avro "double"
    bool active;                          // host bool   -> avro "boolean"
    std::array<std::uint8_t, 4> addr;    // fixed 4 bytes -> avro "fixed"
};
BOOST_DESCRIBE_STRUCT(GoldenRecord, (), (id, counter, score, weight, active, addr))

GoldenRecord make_golden() {
    GoldenRecord r{};
    const std::uint32_t id_v = 0xAABBCCDDu;
    for (int i = 0; i < 4; ++i) {
        r.id.raw[i] = static_cast<std::uint8_t>(id_v >> (8 * (3 - i)));
    }
    const std::int64_t counter_v = -123456789012LL;
    const auto counter_u = static_cast<std::uint64_t>(counter_v);
    for (int i = 0; i < 8; ++i) {
        r.counter.raw[i] = static_cast<std::uint8_t>(counter_u >> (8 * i));
    }
    r.score = 3.5f;
    r.weight = 2.718281828;
    r.active = true;
    r.addr = {192, 168, 1, 42};
    return r;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <out-dir>\n", argv[0]);
        return 2;
    }
    const std::string out_dir = argv[1];

    const GoldenRecord rec = make_golden();

    std::ofstream schema_out(out_dir + "/golden.avsc", std::ios::trunc);
    schema_out << soatins::avro_schema_json<GoldenRecord>("GoldenRecord");
    if (!schema_out) {
        std::fprintf(stderr, "failed to write golden.avsc\n");
        return 1;
    }

    const auto bytes = soatins::to_avro_bytes(rec);
    std::ofstream data_out(out_dir + "/golden.bin", std::ios::binary | std::ios::trunc);
    data_out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!data_out) {
        std::fprintf(stderr, "failed to write golden.bin\n");
        return 1;
    }

    std::printf("wrote %s/golden.avsc + golden.bin (%zu bytes)\n", out_dir.c_str(), bytes.size());
    return 0;
}
