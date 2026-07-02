// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Golden-file generator for the avro_glue OCF streaming writer: pushes rows through a column_sink<T,N>
// whose flush callback is avro_ocf_writer::write_block, so the schema is written once and every full chunk
// becomes one Avro data block encoded straight from the SoA's columns (no per-row struct, no per-block
// schema resend). K=10 rows at N=4 forces 2 full blocks + 1 partial tail block, exactly like
// test_column_sink.cpp, so the golden check also proves multi-block framing (counts/lengths/sync markers)
// is correct, not just single-block encoding.

#include "soatins/avro_glue.hpp"
#include "soatins/endian.hpp"
#include "soatins/reflect.hpp"
#include "soatins/sink.hpp"

#include <boost/describe.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

namespace {

struct StreamRow {
    soatins::be<std::uint32_t> id;    // wire big-endian u32 -> avro "long"
    float value;                       // host float -> avro "float"
    bool flag;                         // host bool  -> avro "boolean"
    std::array<std::uint8_t, 2> tag;  // fixed 2 bytes -> avro "fixed"
};
BOOST_DESCRIBE_STRUCT(StreamRow, (), (id, value, flag, tag))

StreamRow make_row(std::uint32_t i) {
    StreamRow r{};
    const std::uint32_t id_v = i * 5u + 2u;
    for (int k = 0; k < 4; ++k) {
        r.id.raw[k] = static_cast<std::uint8_t>(id_v >> (8 * (3 - k)));
    }
    r.value = static_cast<float>(i) * 1.25f;
    r.flag = (i % 2) == 0;
    r.tag = {static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(i + 1)};
    return r;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <out-file>\n", argv[0]);
        return 2;
    }

    std::ofstream file(argv[1], std::ios::binary | std::ios::trunc);
    if (!file) {
        std::fprintf(stderr, "failed to open %s\n", argv[1]);
        return 1;
    }

    constexpr std::size_t N = 4;
    constexpr std::size_t K = 10;

    soatins::avro_ocf_writer<StreamRow> writer(file, "StreamRow");
    auto sink = soatins::make_column_sink<StreamRow, N>([&](soatins::soa<StreamRow, N>& chunk, std::string&) {
        writer.write_block(chunk, chunk.size());
        return true;
    });

    std::string err;
    for (std::size_t i = 0; i < K; ++i) {
        if (!sink.push(make_row(static_cast<std::uint32_t>(i)), err)) {
            std::fprintf(stderr, "push failed: %s\n", err.c_str());
            return 1;
        }
    }
    if (!sink.finish(err)) {
        std::fprintf(stderr, "finish failed: %s\n", err.c_str());
        return 1;
    }

    if (!file) {
        std::fprintf(stderr, "write error on %s\n", argv[1]);
        return 1;
    }
    std::printf("wrote %zu rows across chunks of %zu to %s\n", K, N, argv[1]);
    return 0;
}
