# pcapng2json

A small, **parser-only** example of nanotins: read a `pcap`/`pcapng` capture and print **one JSON object per
packet** (NDJSON) with the decoded L2/L3/L4 layers. No Lance, no storage backend — just nanotins doing the
scan (`pcap_blocks`) and the decode (`walk_packet` over the Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP
overlays). It's the human-readable counterpart to the columnar `pcapng2lance` converter in the sister
[nanolance](https://github.com/yoavbendor/nanolance) project.

```
pcapng2json capture.pcapng
```

Example output (one line per packet):

```json
{"packet_id":0,"interface_id":0,"timestamp_raw":4294967298,"caplen":46,"origlen":46,"link_type":1,"layers":[{"type":"ethernet","dst":"01:02:03:04:05:06","src":"0a:0b:0c:0d:0e:0f","ethertype":"0x0800"},{"type":"ipv4","src":"10.0.0.1","dst":"10.0.0.2","protocol":17,"ttl":64,"total_length":32},{"type":"udp","src_port":1234,"dst_port":53}]}
```

## What it shows

- **Phase A scan** — `pcapblocks::scan_blocks` detects pcap vs pcapng + endianness and walks the block chain.
- **Per-interface link type** — IDBs build the interface table; each packet's `link_type` comes from its
  interface (reset per section).
- **L2/L3/L4 decode** — `protocols::walk_packet` replays Ethernet → VLAN\* → IPv4/IPv6 → TCP/UDP, invoking a
  callback per header; the example just formats each into JSON.

The conversion core (`pcapng2json.hpp`, `to_ndjson(bytes)`) is header-only, so it's unit-tested in-process
(`test_pcapng2json.cpp`, the `pcapng2json_smoke` CTest) without a sample file or a subprocess.

## For AI agents

**Use this example when** you want to eyeball or diff a capture's decoded L2/L3/L4 layers as text (NDJSON),
or you need a header-only decode helper to unit-test in-process. It is **print-only** — no storage.

**Pick a sibling instead when:** you want columnar output → `pcapng2lance`
([nanolance](https://github.com/yoavbendor/nanolance/tree/main/examples/pcapng2lance), Lance + external
payloads) or `pcapng2parquet`
([nanoarrow2parquet](https://github.com/yoavbendor/nanoarrow2parquet/tree/main/examples/pcapng2parquet),
Parquet).

**Minimal use:** CLI `pcapng2json capture.pcapng` (one JSON object per packet, NDJSON to stdout), or call
the header-only `to_ndjson(bytes)` directly in a test.

**Do**
- Reuse `to_ndjson(bytes)` in-process for tests (no sample file or subprocess needed).
- Treat output as NDJSON — one object per line; stream it line by line.

**Don't**
- Don't expect columns, payloads, or a dataset — this only prints.
- Don't expect PTP / LLDP / SOME/IP here — `walk_packet` decodes Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP
  only (use the columnar examples for the deeper stack).

## Build

Built automatically with a standalone suite build:

```bash
cmake -S . -B build -DNANOTINS_SUITE_BUILD_TESTS=ON
cmake --build build --target pcapng2json
ctest --test-dir build -R pcapng2json_smoke
```
