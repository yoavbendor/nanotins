# nanotins

A small, layered, header-only **C++20** stack for turning raw **pcap/pcapng** packets into columnar
(Arrow) data — one row per PDU, one table per protocol — sequentially or in data-parallel bulk on the
CPU. It is built around one idea: the **declarative wire spec**. Describe a protocol header once with
explicit byte offsets and get, for free, a host read, a device-callable read, an SoA store, and an Arrow
schema — *one spec, four faces*, guaranteed in sync.

The output is plain nanoarrow tables, so any backend persists them: **Lance**
([nanolance](https://github.com/yoavbendor/nanolance)), **Parquet**
([nanoarrow2parquet](https://github.com/yoavbendor/nanoarrow2parquet)), or Arrow IPC. nanotins knows
nothing about storage.

> **📐 Deep dive: the [Architecture & Extension Guide](nanotins/docs/architecture.html)** — an
> illustrated walkthrough of `wire_spec`, the SoA, and the DAG, plus a checkpointed recipe for adding a
> parser. Open in a browser.

## At a glance

- **Parses:** classic pcap + pcapng; L2 Ethernet/VLAN; L3 IPv4 (+options), IPv6 (+ext headers / SRv6);
  L4 TCP/UDP; app gPTP/PTPv2 and SOME/IP; plus anything you add via the DPAR rule engine (LLDP is the
  worked example). Field-checked against **tshark** on real captures.
- **Gives you:** SoA + nanoarrow tables, one per protocol, joined by `packet_id`.
- **Runs:** serial (readable oracle) or bulk (`count → scan → scatter` over stdexec) — **byte-identical**
  output. Parsers are `NANOTINS_HD`, so a GPU executor slots on later.
- **Doesn't do:** reassembly, flow/state tracking, or app-payload parsing beyond gPTP/SOME/IP. Columns
  are scalars or fixed-size binary — no variable-length columns (store offset+length+head snapshot).
- **Needs:** C++20; header-only; deps are nanoarrow + header-only boost (soatins) and stdexec (the bulk
  path only).

## Two header-only libraries

Split so you take exactly the layer you need:

```
soatins  →  nanotins        (each depends only on the one to its left)
reflect     pcap + protocols + bulk
```

| Library | What it gives you | Depends on |
|---|---|---|
| **[`soatins`](soatins/)** | "Describe a struct once → SoA store + Arrow table." The reusable reflection nucleus; knows nothing about packets. | nanoarrow + header-only boost |
| **[`nanotins`](nanotins/)** | pcap/pcapng scanning, the `wire_spec` + `spec_dag` parsing core, the L2/L3/L4 + gPTP/SOME/IP specs, DPAR, and a scheduler-agnostic `bulk_for_each`. | soatins + stdexec |

See **[`nanotins/README.md`](nanotins/README.md)** for the supported-protocol table, the quick-start
decode loop, gotchas, and how to use it **without** pulling in stdexec.

## Quick start

```cpp
#include "nanotins/pcap_blocks.hpp"
#include "nanotins/spec_dag.hpp"
#include "nanotins/dag_decode.hpp"

using G = nanotins::L2L3Graph;
nanotins::dag_tables<G> tables;
nanotins::dag_decode_packet<G>(packet_id, ptr, len, tables, nanotins::kEthRoot);
// each std::get<node_id_v<…Node, G>>(tables) is an SoA table → to_arrow → Lance / Parquet
```

## Build & test

```bash
cmake -S . -B build -DNANOTINS_SUITE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build -L smoke --output-on-failure
```

## Use it in your project

```cmake
add_subdirectory(extern/nanotins)                      # creates soatins::core, nanotins
target_link_libraries(my_app PRIVATE nanotins)         # …the whole packet stack
# or just the nucleus, for any describe→SoA→Arrow use:
target_link_libraries(my_tool PRIVATE soatins::core)
```

| Target | What |
|---|---|
| `soatins::core` | reflection / overlay / SoA / arrow + endian / bits (the reusable nucleus) |
| `nanotins::pcap` | pcap/pcapng block scanner + per-block parse |
| `nanotins::protocols` | wire_spec + spec_dag + L2/L3/L4 specs + serial/bulk decode + gPTP/SOME/IP |
| `nanotins` | umbrella (pcap + protocols, pulls soatins) |

## Sister projects (reference converters)

The same parsing stack drives two end-to-end converters — same dissection, different sink:

- **[`pcapng2lance`](https://github.com/yoavbendor/nanolance/tree/main/examples/pcapng2lance)** — pcapng →
  Lance, with external payload refs. Its `tshark` field-alignment cross-checks are this stack's golden.
- **[`pcapng2parquet`](https://github.com/yoavbendor/nanoarrow2parquet/tree/main/examples/pcapng2parquet)**
  — pcapng → Parquet, one table per layer.

Both vendor nanotins as a submodule; nanotins itself knows nothing about Lance or Parquet.

## License

[Apache-2.0](LICENSE) — see [NOTICE](NOTICE) and [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for
dependency attributions. (Chosen to align with the Arrow/nanoarrow + stdexec ecosystem and for its
explicit patent grant.)
