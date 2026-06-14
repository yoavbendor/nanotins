# nanotins

A small, reusable **C++20** library for parsing **pcap/pcapng** and **L2/L3/L4** packets — sequentially or
in data-parallel bulk — built around one core idea: the **declarative wire-parsing struct spec**. Describe a
protocol header once with explicit byte offsets (`WireSpec<named_field<>, named_bytes_field<>, …>`)
and get, for free:

- a zero-copy **host read** overlay on raw bytes (endianness & bit layout handled by the field types),
- an equivalent **device-callable read** (`NANOTINS_HD`, produces the same columns),
- a flattened **column list** (bitfields expanded to named scalar columns),
- an **SoA** store (`soa<T>`) + a **nanoarrow** schema/array (`arrow_schema<T>()` / `to_arrow<T>()`).

> **📐 New here? Read the [Architecture &amp; Extension Guide](docs/architecture.html)** — an illustrated
> walkthrough of `wire_spec`, the SoA, and the DAG, plus a step-by-step, checkpointed recipe for adding a new
> parser (with where new dependencies belong). Open it in a browser.

The **wire_spec** subsystem (files: `wire_spec.hpp`, `wire_spec_soa.hpp`) replaces hand-written
protocol overlays and gives the **spec_dag** (`spec_dag.hpp`, `dag_decode.hpp`) — a declarative DAG/FSM
dispatcher — a single source of truth. One walk of the DAG decodes serially or as a CPU bulk pass (via
`dag_decode_bulk`), bit-identically. The L2/L3 protocol specs live in
`protocol_specs.hpp`; PTPv2/gPTP extension specs in `protocol_specs_ptp.hpp`. All DAG-emitted PDU tables are
byte-identical to the older hand-written `walk_packet` decoder (verified by the
`test_pdu_table_interop`/`test_pdu_table_lance_interop` suite).

The soatins nucleus (describe→SoA→Arrow) is its own library — **[`soatins`](../soatins)** (namespace `soatins`,
include prefix `soatins/`) — vendorable on its own (depends only on **nanoarrow + header-only boost**,
knows nothing about packets). `nanotins` builds on it, adding pcap/pcapng scanning, the wire_spec + spec_dag
wire-parsing core, the gPTP extension, and scheduler-agnostic `bulk_for_each` (over **stdexec**). Both are
**header-only** — the Phase-B parsers are device-callable (`NANOTINS_HD`), so they live inline in the headers
where device code can see them. Neither knows anything about Lance — they produce nanoarrow tables that any
backend (Lance, Parquet, Arrow IPC) can persist. (A GPU/CUDA executor layer, `gputins`, is developed
separately and not part of this repo; because the parsers are already `NANOTINS_HD`, it slots on top later.)

```
soatins  →  nanotins        (each depends only on the one to its left)
reflect     pcap + protocols + bulk
```

## Read this first

**[docs/nanotins.html](docs/nanotins.html)** — the teaching document: the ideas, the two-phase
parsing pipeline, the CPU bulk path, and a complete worked example of **extending the library with a
new protocol (gPTP / IEEE 802.1AS)**. Open it in a browser.

## Layout

```
../soatins/include/soatins/  reflect, bits, endian, fixed_string, column_traits, describe, arrow_glue
include/nanotins/            wire_spec: wire_spec.hpp, wire_spec_soa.hpp (declarative wire specs)
                             spec_dag: spec_dag.hpp, dag_decode.hpp, dag_bulk.hpp (DAG dispatcher + bulk)
                             protocols: protocol_specs.hpp, protocol_specs_ptp.hpp (L2/L3/L4 specs)
                             protocol_decode.hpp, protocol_decode_bulk.hpp (walk_packet legacy path)
                             bulk: bulk.hpp (scheduler-agnostic bulk_for_each / serial_for_each)
                             pcap: pcap_blocks.hpp (scan_blocks / scan_window / parse_epb — header-only)
                             gptp.hpp (PTPv2 extension, legacy overlay)
tests/                       spec_dag / dag_decode / dag_bulk / wire_spec / protocol_specs
                             protocols / pcap_blocks / bulk / gptp  (reflect / soa_scatter live in soatins)
docs/nanotins.html           the guide
```

## CMake targets

| Target | Kind | What |
|---|---|---|
| `soatins::core` | INTERFACE | reflection / overlay / SoA / arrow + endian / bits (the reusable nucleus) |
| `nanotins::pcap` | INTERFACE | pcap/pcapng block scanner + per-block parse (header-only) |
| `nanotins::protocols` | INTERFACE | wire_spec + spec_dag core + L2/L3/L4 protocol specs + serial/bulk decode + gPTP + bulk_for_each |
| `nanotins` | INTERFACE | umbrella (pcap + protocols, pulls soatins) |

```cmake
add_subdirectory(soatins)                              # the reflection nucleus, on its own…
target_link_libraries(my_tool PRIVATE soatins::core)   #   …for any describe→SoA→Arrow use
add_subdirectory(nanotins)                             # …or the whole packet stack
target_link_libraries(my_app  PRIVATE nanotins)
```

Consumed by [`examples/pcapng2lance`](https://github.com/yoavbendor/nanolance/tree/main/examples/pcapng2lance)
(the reference pcapng→Lance converter) in the sister [nanolance](https://github.com/yoavbendor/nanolance)
project, whose test suite — including the `tshark` field-alignment cross-checks — is this library's golden.
