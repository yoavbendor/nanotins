# nanotins

A small, layered **C++20** stack for turning raw packets into columnar (Arrow) data — sequentially or in
data-parallel bulk on the CPU. It is built around one idea: the **declarative wire spec**. Describe a
protocol header once with explicit byte offsets and get, for free, a host read, a device-callable read, an
SoA store, and an Arrow schema — *one spec, four faces*, guaranteed in sync. (The parsers are already
device-callable, so a GPU/CUDA executor layer slots in on top later without touching the core.)

> **📐 Start here: the [Architecture &amp; Extension Guide](nanotins/docs/architecture.html)** — an
> illustrated walkthrough of `wire_spec`, the SoA, and the DAG, plus a step-by-step, checkpointed recipe for
> adding a new parser. Open it in a browser.

## Two header-only libraries

The stack is split so each piece can be vendored on its own — you take exactly the layer you need:

```
soatins  →  nanotins        (each depends only on the one to its left)
reflect     pcap + protocols + bulk
```

| Library | What it gives you | Depends on |
|---|---|---|
| **[`soatins`](soatins/)** | "Describe a struct once → SoA store + Arrow table." The reusable reflection nucleus; knows nothing about packets. | nanoarrow + header-only boost |
| **[`nanotins`](nanotins/)** | pcap/pcapng scanning, the `wire_spec` + `spec_dag` parsing core, the L2/L3/L4 + gPTP specs, and a scheduler-agnostic `bulk_for_each`. | soatins + stdexec |

Both are **header-only**: the parsers are device-callable (`NANOTINS_HD`), so they live inline in the
headers where device code can see them. They know nothing about any storage backend — they produce
nanoarrow tables that Lance, Parquet, or Arrow IPC can persist.

> **GPU note.** A CUDA/nvexec executor layer (`gputins`) is developed separately and isn't part of this
> repo yet. Because the parsers are already `NANOTINS_HD` device-callable, it slots back on top of `nanotins`
> without changing the core.

## Build & test

The libraries FetchContent their own dependencies, so a standalone build is self-contained:

```bash
cmake -S . -B build -DNANOTINS_SUITE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build -L smoke --output-on-failure
```

## Use it in your project

Add the whole stack with one `add_subdirectory` (e.g. as a git submodule under `extern/nanotins`):

```cmake
add_subdirectory(extern/nanotins)                      # creates soatins::core, nanotins
target_link_libraries(my_app PRIVATE nanotins)         # …the whole packet stack
# or just the nucleus, for any describe→SoA→Arrow use:
target_link_libraries(my_tool PRIVATE soatins::core)
```

### CMake targets

| Target | What |
|---|---|
| `soatins::core` | reflection / overlay / SoA / arrow + endian / bits (the reusable nucleus) |
| `nanotins::pcap` | pcap/pcapng block scanner + per-block parse |
| `nanotins::protocols` | wire_spec + spec_dag core + L2/L3/L4 specs + serial/bulk decode + gPTP + bulk_for_each |
| `nanotins` | umbrella (pcap + protocols, pulls soatins) |

## A sister project

nanotins is consumed by **[nanolance](https://github.com/yoavbendor/nanolance)** — a pcapng → Lance
converter (`examples/pcapng2lance`) whose `tshark` field-alignment cross-checks are this stack's golden
reference. The two repos are independent: nanolance vendors nanotins as a submodule, and nanotins knows
nothing about Lance.

## License

[MIT](LICENSE).
