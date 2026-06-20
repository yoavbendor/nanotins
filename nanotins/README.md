# nanotins

A small, header-only **C++20** library that turns raw **pcap/pcapng** captures into columnar
(nanoarrow) tables — one row per PDU, one table per protocol — on the CPU, sequentially or in
data-parallel bulk. You describe each protocol header once as a declarative **wire spec**, and that one
declaration gives you a host read, a device-callable read, a flattened column list, an SoA store, and an
Arrow schema/array — always in sync.

It produces nanoarrow tables and nothing else: persist them with **Lance**
([nanolance](https://github.com/yoavbendor/nanolance)), **Parquet**
([nanoarrow2parquet](https://github.com/yoavbendor/nanoarrow2parquet)), or Arrow IPC. It knows nothing
about any storage backend.

## What you get

- **pcap + pcapng scanning** (`pcap_blocks.hpp`): classic pcap (either endianness, µs/ns) and pcapng
  (SHB/IDB/EPB/SPB), with a streaming `scan_window` for bounded-memory passes over huge/endless captures.
- **A declarative wire-spec core** (`wire_spec.hpp`, `wire_spec_soa.hpp`): one
  `WireSpec<named_field<…>, named_bytes_field<…>, named_bit_field<…>>` per header → zero-copy overlay,
  bit/endianness handling, flattened columns, SoA, and Arrow — no hand-written byte math.
- **A DAG dispatcher** (`spec_dag.hpp`, `dag_decode.hpp`): chains the specs (Ethernet → VLAN* →
  IPv4/IPv6 → TCP/UDP/…, honoring `ihl`/`data_offset`/`next_header`) and walks each packet once,
  scattering every emitted PDU into its node's table.
- **Serial and bulk decode from one source of truth**: `dag_decode_packet` (serial) and
  `dag_decode_bulk` (a scheduler-agnostic `bulk_for_each` over stdexec) produce **byte-identical** tables
  (guarded by `test_pdu_table_interop`). Serial is the readable oracle; bulk is the throughput path.
- **DPAR** (`dpar.hpp`, `dpar_palette.hpp`): a rule engine to apply *your own* parser to a matched region
  (`eth.ethertype == 0x88CC => lldp …`) without forking the framing DAG — see the
  [LLDP example](../examples/lldp).

## Supported protocols

| Layer | Protocols (spec / DAG node) |
|---|---|
| L2 | Ethernet, 802.1Q VLAN (stacked) |
| L3 | IPv4 (incl. options child table), IPv6 (incl. extension headers: hop-by-hop, routing/SRv6, fragment, dest-opts, AH) |
| L4 | TCP, UDP |
| App | gPTP / PTPv2 (common header + Sync/Follow-Up/Delay-Resp/Announce/Signaling bodies), SOME/IP (+ SD), and anything you add via DPAR (LLDP is the worked example) |

Field-for-field cross-checked against **tshark** on real captures (eth/vlan/ipv4/ipv6/tcp/udp/ptp/SRv6)
by the sister project's test suite.

## Quick start

```cpp
#include "nanotins/pcap_blocks.hpp"   // scan_window, parse_epb
#include "nanotins/spec_dag.hpp"      // L2L3Graph, kEthRoot
#include "nanotins/dag_decode.hpp"    // dag_tables, dag_decode_packet

using G = nanotins::L2L3Graph;
nanotins::dag_tables<G> tables;                 // one growable table per protocol node

// For each Ethernet packet (ptr + len), decode the whole stack in one walk:
nanotins::dag_decode_packet<G>(packet_id, ptr, len, tables, nanotins::kEthRoot);

// Each node's table is SoA + Arrow-ready:
const auto& ipv4 = std::get<nanotins::node_id_v<nanotins::Ipv4Node, G>>(tables);
// ipv4.size(), ipv4.packet_id[i], ipv4.column<I>()  →  to_arrow → Lance / Parquet
```

For the full driver (scan → window → decode → write), read the reference converters:
[`pcapng2lance`](https://github.com/yoavbendor/nanolance/tree/main/examples/pcapng2lance) (Lance) and
[`pcapng2parquet`](https://github.com/yoavbendor/nanoarrow2parquet/tree/main/examples/pcapng2parquet)
(Parquet) — same parsing, different sink.

## Gotchas & things to know

- **Columns are scalars or fixed-size binary.** A column is a `be<>/le<>` scalar, a `bits<>` field, or a
  `std::array<uint8,N>` (→ Arrow `fixed_size_binary`, e.g. MAC/IP/clock_identity). **Variable-length
  values** (an LLDP system name, a packet payload) cannot be a column — store an *offset + length* plus a
  fixed-size head snapshot (the SOME/IP-SD and LLDP rows do exactly this).
- **IPv4 fragmentation:** the L4 (TCP/UDP) header lives only in the first fragment, so a TCP/UDP row is
  emitted **only when `frag_offset == 0`**. Continuation fragments still appear in the `ipv4` table.
  Payload reassembly is not done.
- **Variable-length child records** (IPv4 options, IPv6 SRv6 segments / options) come from a separate
  `ipv4_children_bulk` / `ipv6_children_bulk` pass, not from `dag_decode_packet` alone.
- **The bulk path needs stdexec.** `bulk.hpp` includes `<stdexec/execution.hpp>` unconditionally, so any
  `*_bulk.hpp` header pulls it in. If you only want serial decode, include `dag_decode.hpp` (not
  `dag_bulk.hpp`) and supply your own `for_each` — `serial_for_each` is a plain loop with no scheduler.
- **Header-only + device-callable.** Everything is inline so `NANOTINS_HD` parsers stay visible to device
  code. Requires **C++20** (concepts, templated lambdas).
- **No reassembly, no flow tracking, no TLS/HTTP/app-payload parsing.** This is per-packet header
  dissection. App protocols beyond gPTP/SOME/IP are DPAR's job (you write the parser).

## Performance

The kernels are light and the pipeline is memory-bandwidth-bound: on an 8-core host a 1.9 GB capture
decodes in ~0.7 s, and serial vs. bulk are within noise (one thread already saturates read bandwidth).
The bulk path's real payoff is a **GPU** executor (swap the scheduler) — the parsers are already
`NANOTINS_HD`; the CUDA/nvexec layer (`gputins`) is developed separately and not vendored here yet.

## Layout

```
../soatins/include/soatins/  endian, bits, fixed_string, column_traits, describe, reflect, arrow_glue
include/nanotins/  wire_spec.hpp, wire_spec_soa.hpp        declarative wire specs (overlay + SoA + Arrow)
                   spec_dag.hpp, dag_decode.hpp            DAG dispatcher + serial decode
                   dag_bulk.hpp, *_children_bulk.hpp       bulk (count→scan→scatter) decode (stdexec)
                   protocol_specs.hpp, protocol_specs_ptp.hpp, protocol_specs_someip.hpp   the specs
                   protocol_decode.hpp                     legacy hand-written walk_packet (kept as oracle)
                   bulk.hpp                                bulk_for_each / serial_for_each
                   pcap_blocks.hpp                         pcap/pcapng scan + per-block parse
                   dpar*.hpp                               rule engine for user-added parsers
tests/             spec_dag / dag_decode / wire_spec / protocol_specs / pcap_blocks / gptp / dpar
```

## CMake targets

| Target | Kind | What |
|---|---|---|
| `soatins::core` | INTERFACE | reflection / overlay / SoA / Arrow + endian / bits (the reusable nucleus) |
| `nanotins::pcap` | INTERFACE | pcap/pcapng block scanner + per-block parse |
| `nanotins::protocols` | INTERFACE | wire_spec + spec_dag + L2/L3/L4 + PTP/SOME/IP + serial/bulk decode (links stdexec) |
| `nanotins` | INTERFACE | umbrella (pcap + protocols, pulls soatins) |

```cmake
add_subdirectory(soatins)                              # the reflection nucleus, on its own…
target_link_libraries(my_tool PRIVATE soatins::core)   #   …for any describe→SoA→Arrow use
add_subdirectory(nanotins)                             # …or the whole packet stack
target_link_libraries(my_app  PRIVATE nanotins)
```

> **Avoiding stdexec:** linking `nanotins` (or `nanotins::protocols`) FetchContents stdexec at configure
> time, even if you only decode serially. To skip it, don't `add_subdirectory(nanotins)`; instead link
> `soatins::core` and add `nanotins/include` to your include path directly, and include only the
> non-`*_bulk` headers. (This is exactly what `pcapng2parquet` does.)

## Build & test

```bash
cmake -S . -B build -DNANOTINS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build -L smoke --output-on-failure
```

## Extending it

Adding a protocol is: write a `WireSpec` for its header, add a `spec_dag` node + the dispatch edge from
its parent, done — you get the table, the bulk path, and the Arrow mapping for free. The illustrated,
checkpointed recipe is in **[docs/architecture.html](docs/architecture.html)** (open in a browser); for
an app protocol with no fixed header (variable TLVs), use DPAR — see the [LLDP example](../examples/lldp).
