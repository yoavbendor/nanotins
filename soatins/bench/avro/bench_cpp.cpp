// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// avro_glue.hpp benchmark: streams WideRow through column_sink<WideRow,N> -> avro_ocf_writer, the same
// path a real bulk pipeline would use. See ../README.md for the row schema/formulas this must match across
// all four language variants, and for why the comparison favors a compile-time-known struct.

#include "soatins/avro_glue.hpp"
#include "soatins/endian.hpp"
#include "soatins/reflect.hpp"
#include "soatins/sink.hpp"

#include <boost/describe.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

namespace {

struct WideRow {
    soatins::be<std::uint32_t> id;  // wire big-endian -> avro long
    std::int8_t s8;
    std::uint8_t u8f;
    std::int16_t s16;
    std::uint16_t u16f;
    std::int32_t s32;
    std::uint32_t u32f;
    std::int64_t s64;
    std::uint64_t u64f;
    float f1;
    float f2;
    double d1;
    double d2;
    bool b1;
    bool b2;
    bool b3;
};
BOOST_DESCRIBE_STRUCT(WideRow, (), (id, s8, u8f, s16, u16f, s32, u32f, s64, u64f, f1, f2, d1, d2, b1, b2, b3))

WideRow make_row(std::uint64_t i) {
    WideRow r{};
    const auto id_v = static_cast<std::uint32_t>(i);
    for (int k = 0; k < 4; ++k) {
        r.id.raw[k] = static_cast<std::uint8_t>(id_v >> (8 * (3 - k)));
    }
    r.s8 = static_cast<std::int8_t>(static_cast<std::int32_t>(i % 256) - 128);
    r.u8f = static_cast<std::uint8_t>(i % 256);
    r.s16 = static_cast<std::int16_t>(static_cast<std::int32_t>(i % 65536) - 32768);
    r.u16f = static_cast<std::uint16_t>(i % 65536);
    r.s32 = static_cast<std::int32_t>(static_cast<std::int64_t>(i) * 3 - 100000);
    r.u32f = static_cast<std::uint32_t>(i * 7);
    r.s64 = -static_cast<std::int64_t>(i) * 123456789;
    r.u64f = i * 987654321ULL;
    r.f1 = static_cast<float>(i) * 0.5f;
    r.f2 = -static_cast<float>(i) * 1.25f;
    r.d1 = static_cast<double>(i) * 2.718281828;
    r.d2 = -static_cast<double>(i) * 3.14159265;
    r.b1 = (i % 2) == 0;
    r.b2 = (i % 3) == 0;
    r.b3 = (i % 5) == 0;
    return r;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <out-file> <n-rows>\n", argv[0]);
        return 2;
    }
    const std::string out_path = argv[1];
    const long n = std::atol(argv[2]);

    std::ofstream file(out_path, std::ios::binary | std::ios::trunc);
    constexpr std::size_t N = 4096;

    soatins::avro_ocf_writer<WideRow> writer(file, "WideRow");
    auto sink = soatins::make_column_sink<WideRow, N>([&](soatins::soa<WideRow, N>& chunk, std::string&) {
        writer.write_block(chunk, chunk.size());
        return true;
    });

    std::string err;
    const auto t0 = std::chrono::steady_clock::now();
    for (long i = 0; i < n; ++i) {
        sink.push(make_row(static_cast<std::uint64_t>(i)), err);
    }
    sink.finish(err);
    file.flush();
    const auto t1 = std::chrono::steady_clock::now();

    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::printf("c++ avro_glue: wrote %ld rows in %.2f ms (%.1f ns/row)\n", n, ms, ms * 1e6 / static_cast<double>(n));
    return 0;
}
