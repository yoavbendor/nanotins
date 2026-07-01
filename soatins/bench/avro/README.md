# avro_glue write benchmark

How `avro_glue.hpp`'s reflection-driven Avro encoding compares, throughput-wise, to writing the same data
with each language's own Avro library. Not part of the correctness test suite (`ctest`) — this is a
performance comparison across four different toolchains, run manually.

## Run it

```bash
soatins/bench/avro/run_bench.sh [n-rows]   # defaults to 500000
```

Prerequisites: a C++20 compiler, `libboost-dev` (or any boost providing `describe`/`mp11` headers),
`libavro-dev` (avro-c), a Rust toolchain (`cargo`), and `pip install fastavro`.

`run_bench.sh` rewrites the "Latest run" section below every time it completes, but only after
`verify.py` has confirmed every writer's output actually round-trips through fastavro correctly — a
fast-but-wrong writer never gets recorded. Numbers are this machine's, not a portable claim; re-run before
citing them.

## Latest run

<!-- BENCH_RESULTS_START -->

Last run: 2026-07-01 22:16 UTC, commit `42a3db4`, 500,000 rows, on `Intel(R) Xeon(R) Processor @ 2.80GHz`.

| writer | ns/row | rows/sec | vs fastest |
|---|---|---|---|
| C++ `avro_glue.hpp` | 135.6 | 7,374,631 | 1.0x (fastest) |
| C `avro-c` (generic) | 497.8 | 2,008,839 | 3.7x |
| Rust `apache-avro` (serde) | 499.4 | 2,002,403 | 3.7x |
| Python `fastavro` | 4857.6 | 205,863 | 35.8x |

<!-- BENCH_RESULTS_END -->

## What's compared

All four write the same `WideRow` — 16 fields chosen to be primitive types every one of these libraries'
"fastest available, no-runtime-schema-surprises" path supports natively (no variable-length string/bytes,
no `fixed` array — those hit an avro-c/serde edge case, see below):

| field | type | avro type | value for row `i` |
|---|---|---|---|
| `id` | u32 | long | `i` |
| `s8` | i8 | int | `(i % 256) - 128` |
| `u8f` | u8 | int | `i % 256` |
| `s16` | i16 | int | `(i % 65536) - 32768` |
| `u16f` | u16 | int | `i % 65536` |
| `s32` | i32 | int | `i*3 - 100000` |
| `u32f` | u32 | long | `i*7` |
| `s64` | i64 | long | `-i*123456789` |
| `u64f` | u64 | long | `i*987654321` |
| `f1`,`f2` | f32 | float | `i*0.5`, `-i*1.25` |
| `d1`,`d2` | f64 | double | `i*2.718281828`, `-i*3.14159265` |
| `b1`,`b2`,`b3` | bool | boolean | `i%2==0`, `i%3==0`, `i%5==0` |

Each bench writes an Object Container File (`null` codec, schema written once) and prints
`... wrote N rows in ... ms (... ns/row)`. `verify.py` then reads every file back with fastavro and checks
every row against the table above, so a fast-but-wrong writer can't win.

- **`bench_cpp.cpp`** — `avro_glue.hpp`: `column_sink<WideRow,4096>` flushing into `avro_ocf_writer`,
  encoding straight from the SoA's columns (see `avro_glue.hpp`'s header comment).
- **`bench_c.c`** — avro-c's *generic* value API (`avro_value_set_*` by field name). avro-c also has a
  *specific* API generated from the schema (codegen) that would likely close some of the gap below — not
  used here because requiring codegen is exactly what `avro_glue.hpp` exists to avoid.
- **`bench_rust/`** — `apache-avro`'s `Writer::append_ser` with a `#[derive(Serialize)]` struct: the
  *typed* path, not the dynamic `Record`/`Value` builder (which is ~15-20% slower in informal testing —
  still dynamically-typed dispatch either way, just less indirection).
- **`bench_python.py`** — `fastavro.writer()` over a generator of dicts.

## Why the gap

`avro_glue.hpp` only works for a `T` whose layout is known at compile time — `for_each_column<T>` fully
unrolls and inlines, so there is no runtime schema interpretation, no dynamic field lookup, and no
per-field type tag to branch on while encoding. Every other library here is designed to accept a schema
*at runtime*, so they all pay for dynamic dispatch (by-name field lookup, a tagged `Value` union, a serde
visitor) on every field of every row — that flexibility is the actual product being sold, and this
benchmark isn't a fair indictment of it. The comparison is only meaningful for the question `avro_glue.hpp`
was built to answer: can a no-codegen, compile-time-reflected encoder be fast, and how fast relative to
purpose-built libraries paying for runtime flexibility we don't need here.
