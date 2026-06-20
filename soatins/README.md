# soatins

**Describe a wire-shaped struct once → get an SoA store and an Arrow table.** soatins is the reflection
nucleus split out of [`nanotins`](../nanotins): the reusable trick, with nothing packet-specific. Put a
packed struct of endianness-aware fields behind one `BOOST_DESCRIBE_STRUCT` line and you get, for free:

- a zero-copy **`overlay<T>(bytes)`** view onto raw wire bytes (`be<>`/`le<>`/`bits<>` handle byte order
  and bit layout),
- a flattened **column list** — `columns_of<T>`, with `bits<>` bitfields expanded into named scalar
  columns,
- a **Struct-of-Arrays** store, `soa<T>` (`.store(i, row)`), plus a device-fillable view
  (`soa<T>::raw()` → `soa_ptrs<T>`, and a free `scatter(ptrs, i, row)`) for filling columns from a kernel,
- a **nanoarrow** `ArrowSchema`/`ArrowArray` — `arrow_schema<T>()` / `to_arrow<T>(soa)` — so any backend
  (Lance, Parquet, Arrow IPC) can persist it.

Depends only on **nanoarrow** and **header-only boost** (`describe` + `mp11`). No stdexec, no CUDA, no
Lance. Namespace `soatins`, include prefix `soatins/`. Requires **C++20**.

## Quick start

```cpp
#include "soatins/bits.hpp"
#include "soatins/reflect.hpp"
#include "soatins/arrow_glue.hpp"
#include <boost/describe.hpp>

struct Sample {                       // a wire-shaped record
    soatins::be<std::uint32_t> id;    // big-endian on the wire, host order when read
    soatins::be<std::uint16_t> kind;
    std::uint8_t                flags;
    std::array<std::uint8_t, 6> mac;  // → Arrow fixed_size_binary[6]
};
BOOST_DESCRIBE_STRUCT(Sample, (), (id, kind, flags, mac))   // the one line

soatins::soa<Sample> rows;
rows.resize(n);
rows.store(0, soatins::overlay<Sample>(bytes));        // zero-copy read → columnar store
ArrowSchema schema; ArrowArray arr; std::string err;
soatins::arrow_schema<Sample>(schema, err);            // stable schema (REQUIRED columns)
soatins::to_arrow(rows, arr, err);                     // hand to Lance / Parquet / IPC
```

## What a column can be

| C++ field | Arrow column | Notes |
|---|---|---|
| `std::int8/16/32/64_t`, `std::uint8/16/32/64_t` | `int*` / `uint*` | host-order |
| `be<T>` / `le<T>` | the underlying int type | byte-swapped on read into host order |
| `bits<Word, field<"a",N>, …>` | one scalar column per named field | bitfields flatten to columns |
| `float`, `double` | `float` / `double` | |
| `std::array<std::uint8_t, N>` | `fixed_size_binary[N]` | MAC / IPv4 / IPv6 / clock_identity |

All columns are emitted **REQUIRED** (non-nullable). For fixed-width columns the Arrow data buffer is the
SoA column's own storage (zero-copy bulk append).

## Gotchas & limits

- **No variable-length columns.** Strings, byte blobs, and lists are *not* supported as columns — soatins
  is for fixed-shape records. Store variable data as an *offset + length* plus a fixed-size
  `std::array<uint8,N>` head snapshot (the LLDP / SOME/IP-SD rows do this), or keep it out of the table.
- **`bool` as a row field is awkward** downstream: Arrow stores bool as 1 bit, but some byte-wide writer
  paths reject it. Prefer `std::uint8_t` for flags if your sink is strict (nanolance currently is).
- **Every struct needs its `BOOST_DESCRIBE_STRUCT` line** — that macro is what drives the columns. Field
  order in the macro is the column order.
- **Packed/POD only.** Fields must be the supported wire types above; the overlay reads bytes directly, so
  no virtuals, no pointers, no padding assumptions beyond the declared fields.
- **Nullability / nested structs / dictionaries are out of scope.** Those live in the storage backends
  (nanolance / nanoarrow2parquet), not here.

## Layout

```
include/soatins/   endian, bits, fixed_string   field types (byte order + bit layout)
                   describe, column_traits       reflection: members → flattened columns
                   reflect                        soa<T>, soa_ptrs<T>, scatter, columns_of
                   arrow_glue                     arrow_schema<T>() / to_arrow<T>()
                   portability                    NANOTINS_HD (host/device annotation)
tests/             reflect_smoke, soa_scatter, soa_fixed, soa_fixed_arrow, column_sink
```

## CMake

```cmake
add_subdirectory(soatins)
target_link_libraries(my_tool PRIVATE soatins::core)
```

If your parent build already defines a `nanoarrow_static` target, soatins reuses it; otherwise it
FetchContents nanoarrow. Used by [`nanotins`](../nanotins) (the pcap/pcapng + L2/L3/L4 parser) and the
[`pcapng2lance`](https://github.com/yoavbendor/nanolance/tree/main/examples/pcapng2lance) /
[`pcapng2parquet`](https://github.com/yoavbendor/nanoarrow2parquet/tree/main/examples/pcapng2parquet)
reference converters.
