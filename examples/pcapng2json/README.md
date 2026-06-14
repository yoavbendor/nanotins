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

## Build

Built automatically with a standalone suite build:

```bash
cmake -S . -B build -DNANOTINS_SUITE_BUILD_TESTS=ON
cmake --build build --target pcapng2json
ctest --test-dir build -R pcapng2json_smoke
```
