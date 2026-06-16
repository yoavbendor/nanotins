<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Yoav Bendor -->

# Implementation plan: IPv6 extension headers + TLV/SRv6 parsing in the DAG

**Audience: the implementing AI/engineer.** This is a prescriptive, phase-gated plan. Do the phases **in
order**. Do **not** start a phase until the previous phase's **GATE** is green. Each phase is independently
committable. If a gate fails, fix it before proceeding — never skip a gate.

Companion reading (same folder): **[`the_case_for_learning_from_vbvx.md`](the_case_for_learning_from_vbvx.md)**
(why) and **[`architecture.html`](architecture.html)** (the wire_spec / SoA / DAG machinery you are
extending). The wire-format reference you need is **embedded below (§2)** — you do not need to fetch
anything.

---

## 0.0 Background the code doesn't spell out (read this — it defines the terms used below)

You have the **nanotins** and **nanolance** source in context, but a few terms and intentions in this plan
come from project history rather than the code. They are defined here once:

- **"GPU transition" / "(future) GPU" / "GPU re-introduction".** nanotins currently ships **two** header-only
  libraries (`soatins`, `nanotins`). A CUDA/nvexec executor layer called **`gputins`** was built but is **not
  in this repo right now** — it is developed separately and intended to be layered back on later (see this
  repo's top-level `README.md` and `the_case_for_learning_from_vbvx.md`). That is why every parsing primitive
  is **`NANOTINS_HD`** (a macro marking a function callable on both host and GPU device — see
  `soatins/portability.hpp`) and why this work must stay **C++20 + device-safe**: so the future `gputins`
  layer can compile these exact headers under clang-cuda/nvcc unchanged. Wherever this plan says "GPU
  transition", "device-safe", or "(future) gpu", that is the only thing it means.
- **vbvx / `SRv6TlvIterator` / `validate_srh_bounds()`.** **vbvx** is an *external* C++ library analysed in
  `the_case_for_learning_from_vbvx.md`. Its `SRv6TlvIterator` is a bounds-checked, allocation-free cursor
  over `[type][len][value]` records; `validate_srh_bounds()` is its up-front "check all the lengths once,
  then trust them" gate. **We borrow the pattern, not the code** — you never need vbvx itself; everything
  required is in this plan.
- **"serial == bulk" (and why it matters).** nanotins decodes a batch of packets two ways that must produce
  **byte-identical** output: a simple sequential pass (`dag_decode.hpp`) and a data-parallel bulk pass
  (`dag_bulk.hpp`, using *count → exclusive prefix-sum → scatter*). The bulk pass is also the exact template
  the future GPU executor follows, so "serial == bulk == (future) gpu" just means "one decode, three
  executors, identical bytes". Any new table must pass this equality.
- **Per-PDU tables keyed by `packet_id`.** nanotins emits each protocol layer as its **own** table
  (`ethernet`, `vlan`, `ipv4`, `tcp`, …), **one row per occurrence**, and every row carries the
  originating packet's `packet_id` so rows can be joined back to the packet. A layer that can occur 0..N
  times per packet (like a VLAN tag, or — in this plan — an extension header or a segment) simply produces
  0..N rows in its table. This is the idiom you will extend; it is already how the `vlan` table works.
- **`fixed_size_binary` and "fixed-width SoA".** The SoA → Arrow conversion (see `wire_spec_soa.hpp` and
  soatins `arrow_glue.hpp`) currently emits only **fixed-width scalar columns** (integers) and
  **`fixed_size_binary(N)`** (a column of fixed-N byte blobs — e.g. a 16-byte IPv6 address). It has **no**
  Arrow `List<>`/nested-type support today. (You can verify this in those files.) This is exactly why §3.1
  models variable-length data as extra tables instead of `List<>` columns.
- **The tshark oracle + "skips 77".** The strongest correctness check compares our decoded fields against
  **tshark** (the Wireshark CLI) on real captures. Those tests (in nanolance) return CTest exit code **77**,
  which CTest treats as "skip", when tshark isn't installed — so CI without tshark stays green.

---

## 0. Hard invariants (read first — violating any of these fails review)

1. **C++20 only.** No C++23 features anywhere in this work. (Reason: the GPU re-introduction compiles these
   headers under clang-cuda/nvcc; nvcc C++23 is immature.)
2. **Device-safety / GPU-transition.** All parsing primitives that run inside the decode walk must be
   `NANOTINS_HD` and obey the existing rules in `pcap_blocks.hpp`/`protocol_decode.hpp`:
   - **No** `std::span`, `std::optional`, `std::vector`, `std::string`, exceptions, virtuals, RTTI, or
     allocation in any `NANOTINS_HD` function.
   - Use the existing POD `Bytes` (ptr+len) and raw `const std::uint8_t*` + explicit bounds checks.
   - New cursor/iterator types must be **trivially copyable PODs** (so a GPU kernel can `memcpy` them), like
     `node_counts` / `dag_sink` in `dag_bulk.hpp`.
   - Bounded loops only (compile-time or explicit max), like `kMaxWalkSteps`.
   - Host-only helpers (table assembly, std containers) are fine **only** outside `NANOTINS_HD`.
3. **Arrow compatibility preserved.** Every new column/table must be expressible with the existing
   fixed-width + `fixed_size_binary` SoA (no new Arrow type is required for this plan — see §3 "child-table
   model"). Do **not** invent encodings.
4. **Determinism.** Dispatch stays exact-key (no heuristics) so `serial == bulk == (future) gpu`
   bit-for-bit. Every new table must pass the serial-vs-bulk equality gate.
5. **Additive, no regressions.** Existing tables (eth/vlan/ipv4/ipv6/tcp/udp/gptp/ptp_*) and all existing
   tests must remain byte-identical. Run the full suite after every phase.
6. **Validate before you read.** Mirror vbvx's `validate_srh_bounds()` discipline: one up-front bounds gate
   per variable region, then the inner accessors assume safety.

---

## 1. Goal

Teach the IPv6 branch of the DAG (`spec_dag.hpp`) to **walk the IPv6 extension-header chain** and parse the
TLV/segment-list payloads it carries (Hop-by-Hop options, Destination Options, Routing/**SRv6 SRH**,
Fragment, AH; ESP/No-Next terminate). This:

- **Fixes a live correctness bug**: today `Ipv6Node` assumes a fixed 40-byte header and reads `next_header`
  as the L4 protocol, so any IPv6 packet with extension headers **mis-decodes L4** (no TCP/UDP row, wrong
  payload boundary).
- **Adds coverage**: extension-header tables, IPv6 options, and SRv6 segment lists — using the
  `SRv6TlvIterator` *pattern* (a validated, allocation-free, bounds-checked cursor) generalised to all IPv6
  TLVs.

End state: correct L4 on IPv6+ext packets, plus new per-record tables: `ipv6_ext`, `ipv6_srh`,
`ipv6_srh_segment`, `ipv6_opt`, `ipv6_fragment`.

---

## 2. Embedded wire-format reference (authoritative for this work)

Cross-check everything here against **RFC 8200** (IPv6, §4 extension headers, §4.2 options),
**RFC 8754** (SRv6 SRH), and **tshark** (the test oracle). If this section and an RFC/tshark disagree, the
RFC/tshark wins — fix the plan.

### 2.1 The chain

IPv6 base header is a fixed **40 bytes**. Its `next_header` (byte 6) and every extension header's own
`next_header` field form a chain. A value is an **extension header type** or an **upper-layer protocol**:

| `next_header` | Header | This header's length | Has TLVs? |
|---|---|---|---|
| 0   | Hop-by-Hop Options | `(hdr_ext_len + 1) * 8` | **yes** (options) |
| 43  | Routing (type 4 = **SRv6 SRH**) | `(hdr_ext_len + 1) * 8` | segment list + TLVs |
| 44  | Fragment | **fixed 8** | no |
| 60  | Destination Options | `(hdr_ext_len + 1) * 8` | **yes** (options) |
| 51  | Authentication Header (AH) | `(ah_len_field + 2) * 4` | no (treat opaque) |
| 50  | ESP | encrypted → **stop walk** | no |
| 59  | No Next Header | **stop walk** | no |
| 135 | Mobility | `(hdr_ext_len + 1) * 8` | (out of scope v1; skip generically) |
| 6 / 17 / 58 / 132 / … | TCP / UDP / ICMPv6 / SCTP / … | **not an ext header — this is L4** | — |

Common preamble for the `*8`-length headers (Hop-by-Hop, Routing, Dest-Opts, Mobility):
`byte[0]=next_header`, `byte[1]=hdr_ext_len` (8-byte units, **not** counting the first 8 bytes).
**Fragment** (44): `byte[0]=next_header`, `byte[1]=reserved`, fixed 8 bytes — do **not** use byte[1] for
length. **AH** (51): `byte[0]=next_header`, `byte[1]=payload_len` (4-byte units, minus 2) → length
`(byte[1]+2)*4`.

### 2.2 IPv6 options TLV format (Hop-by-Hop / Destination Options) — RFC 8200 §4.2

Options live in the header body after the 2-byte preamble, filling to the header's end. Each option:

```
Pad1 :  [ type=0 ]                         (exactly 1 byte, no length, no value)
other:  [ type ][ opt_data_len ][ value: opt_data_len bytes ]    (PadN is type=1 with zero value)
```

`opt_data_len` is the length of the **value only** (not counting the 2-byte type+len). The high 3 bits of
`type` are action/mutability flags (record `type` raw; do not interpret for v1).

### 2.3 SRv6 Segment Routing Header (SRH) — RFC 8754 §2

Routing extension header (`next_header`=43) with `routing_type`=4:

```
byte 0 : next_header        byte 1 : hdr_ext_len      byte 2 : routing_type (=4)
byte 3 : segments_left      byte 4 : last_entry        byte 5 : flags
byte 6-7 : tag (u16, big-endian)
byte 8.. : Segment List  — (last_entry + 1) entries, each a 16-byte IPv6 address, reverse order
then    : optional TLVs   — [type][len][value], bounded by the SRH end ((hdr_ext_len+1)*8)
```

Number of segments = `last_entry + 1`. Segment list bytes = `num_segments * 16`. TLV region =
`[8 + num_segments*16, (hdr_ext_len+1)*8)`. **Validate** that the segment list and TLV region fit inside the
SRH and the SRH fits inside the captured packet before reading. (SRH TLV padding/types per RFC 8754 §2.1 —
walk generically as `[type][len][value]`; verify exact pad-TLV handling against tshark.)

---

## 3. Design (what to build)

### 3.1 The child-table model (KEY DECISION — keeps it Arrow-simple)

Do **not** introduce Arrow `List<>` columns in this plan. Model variable-length data the way nanotins
already models VLAN tags: **extra per-record tables keyed by `packet_id`**, with the existing fixed-width +
`fixed_size_binary` SoA and the existing count→scan→scatter machinery (which already supports a variable
number of rows per packet). New tables:

| Table | One row per | Columns (all fixed-width) |
|---|---|---|
| `ipv6_ext` | each extension header in the chain | `packet_id:u64, order:u8, header_type:u8, next_header:u8, hdr_ext_len:u8, byte_length:u16` |
| `ipv6_fragment` | each Fragment header | `packet_id:u64, next_header:u8, frag_offset:u16, more_fragments:u8, identification:u32` |
| `ipv6_srh` | each SRH | `packet_id:u64, next_header:u8, hdr_ext_len:u8, segments_left:u8, last_entry:u8, flags:u8, tag:u16, num_segments:u8, num_tlvs:u16` |
| `ipv6_srh_segment` | each segment in an SRH | `packet_id:u64, srh_order:u8, segment_index:u8, address:fixed_size_binary(16)` |
| `ipv6_opt` | each Hop-by-Hop/Dest-Opt option | `packet_id:u64, container_type:u8, opt_type:u8, opt_len:u8` (value bytes are out of scope v1; store offset `value_off:u32` for a later phase) |

This reuses everything; **no new Arrow capability is needed**. (Arrow `List<>` columns remain a possible
future enhancement, noted in the case doc — out of scope here.)

### 3.2 The TLV/segment cursor primitive (the `SRv6TlvIterator` generalisation)

New header **`nanotins/include/nanotins/tlv.hpp`** — pure POD, `NANOTINS_HD`, C++20:

```cpp
#pragma once
// SPDX-License-Identifier: Apache-2.0
#include "soatins/portability.hpp"   // NANOTINS_HD
#include <cstddef>
#include <cstdint>

namespace nanotins {

// One decoded TLV record. value points into the packet buffer (null for a 1-byte pad).
struct tlv_record {
    std::uint8_t  type;
    std::uint8_t  length;        // value length in bytes (0 for Pad1)
    const std::uint8_t* value;   // -> packet bytes (nullptr for Pad1)
};

// Padding convention for the TLV space being walked.
enum class tlv_pad { ipv6_options };  // type 0 = Pad1 (1 byte), type 1 = PadN. Add others as needed.

// Bounds-checked, allocation-free cursor over [type][len][value] records between [p, end).
// Trivially copyable POD: safe to capture into a GPU kernel.
struct tlv_cursor {
    const std::uint8_t* p   = nullptr;
    const std::uint8_t* end = nullptr;
    tlv_pad pad = tlv_pad::ipv6_options;

    NANOTINS_HD bool next(tlv_record& out) noexcept {
        if (p >= end) return false;
        const std::uint8_t t = p[0];
        if (pad == tlv_pad::ipv6_options && t == 0) {     // Pad1
            out = tlv_record{0, 0, nullptr};
            p += 1;
            return true;
        }
        if (p + 2 > end) return false;                    // need type+len
        const std::uint8_t len = p[1];
        if (p + 2 + len > end) return false;              // value must fit
        out = tlv_record{t, len, p + 2};
        p += 2 + len;
        return true;
    }
};

// Count records without emitting (for the count pass). Device-safe.
NANOTINS_HD inline std::uint32_t tlv_count(const std::uint8_t* p, const std::uint8_t* end,
                                           tlv_pad pad) noexcept {
    tlv_cursor c{p, end, pad}; tlv_record r{}; std::uint32_t n = 0;
    while (c.next(r)) ++n;
    return n;
}

// Fixed-stride repeat (e.g. SRv6 segment list: stride 16). Returns the i-th record start or nullptr.
NANOTINS_HD inline const std::uint8_t* repeat_at(const std::uint8_t* base, std::uint32_t count,
                                                 std::uint32_t stride, const std::uint8_t* end,
                                                 std::uint32_t i) noexcept {
    if (i >= count) return nullptr;
    const std::uint8_t* q = base + std::size_t{i} * stride;
    return (q + stride <= end) ? q : nullptr;
}

}  // namespace nanotins
```

### 3.3 The extension-header chain walk + DAG nodes

Each extension-header *type* becomes a DAG node (mirroring `Ipv4Node`/`TcpNode` in `spec_dag.hpp`). All of
them dispatch `next` on **their own** `next_header` (byte 0) via a shared `ip6_next_dispatch`, so the graph
self/cross-loops through the chain until it reaches L4 or a terminator. `walk`'s `kMaxWalkSteps` already
bounds it.

Add to `protocol_specs.hpp` the ext-header `WireSpec`s (preamble + SRH/Fragment fields), e.g.:

```cpp
// common *8-length ext header preamble (Hop-by-Hop / Dest-Opts)
using Ipv6ExtOptSpec = WireSpec<
    named_field<decltype("next_header"_fld), 0, std::uint8_t, wire_endian::big>,
    named_field<decltype("hdr_ext_len"_fld), 1, std::uint8_t, wire_endian::big>>;

// SRv6 SRH fixed part (segment list + TLVs handled by the cursor, not the spec)
using Ipv6SrhSpec = WireSpec<
    named_field<decltype("next_header"_fld),   0, std::uint8_t,  wire_endian::big>,
    named_field<decltype("hdr_ext_len"_fld),   1, std::uint8_t,  wire_endian::big>,
    named_field<decltype("routing_type"_fld),  2, std::uint8_t,  wire_endian::big>,
    named_field<decltype("segments_left"_fld), 3, std::uint8_t,  wire_endian::big>,
    named_field<decltype("last_entry"_fld),    4, std::uint8_t,  wire_endian::big>,
    named_field<decltype("flags"_fld),         5, std::uint8_t,  wire_endian::big>,
    named_field<decltype("tag"_fld),           6, std::uint16_t, wire_endian::big>>;
// Fragment + AH specs likewise (see §2.1 for fields/lengths).
```

Add the IPv6 next-header dispatch (replaces `ip_proto_dispatch` for the IPv6 branch only; IPv4 keeps the
simple one):

```cpp
template <class Graph>
NANOTINS_HD inline int ip6_next_dispatch(std::uint64_t nh) noexcept {
    return match_edges<Graph,
        edge<0,   Ipv6HopByHopNode>, edge<43,  Ipv6RoutingNode>, edge<44, Ipv6FragmentNode>,
        edge<60,  Ipv6DestOptNode>,  edge<51,  Ipv6AhNode>,
        edge<6,   TcpNode>,          edge<17,  UdpNode>>(nh);
    // 50 (ESP) and 59 (No-Next) and unknown -> -1 (stop) automatically.
}
```

Each ext node: `advance` = its length rule (§2.1); `next` = `ip6_next_dispatch<G>(next_header_byte)`.
`Ipv6Node::advance` stays 40, but `Ipv6Node::next` now calls `ip6_next_dispatch` (not `ip_proto_dispatch`).
Add the new nodes to `L2L3Graph`.

> The fixed per-header rows (`ipv6_ext`, `ipv6_srh`, `ipv6_fragment`, …) come for free from the standard
> one-spec-per-node `dag_tables` mechanism. The **variable child rows** (`ipv6_srh_segment`, `ipv6_opt`)
> need the cursor + a child-emission pass — that is Phase 5, the hard part.

---

## 4. Phases & GATES

> Run **the full existing test suite** (`ctest -L smoke`) at the end of every phase; "GATE green" always
> includes "no pre-existing test regressed".

### Phase 0 — Baseline & fixtures
- **Do:** Read `spec_dag.hpp`, `dag_decode.hpp`, `dag_bulk.hpp`, `protocol_decode.hpp`, `wire_spec.hpp`,
  `protocol_specs.hpp`, and `tests/pcap_fixtures.hpp`. Add to `pcap_fixtures.hpp` builders for synthetic
  IPv6 packets: (a) plain IPv6+UDP (no ext), (b) IPv6 + Hop-by-Hop(1 PadN) + TCP, (c) IPv6 + Fragment + UDP,
  (d) IPv6 + SRH(2 segments, 0 TLVs) + UDP, (e) IPv6 + SRH(3 segments, 1 HMAC-shaped TLV) + Hop-by-Hop +
  TCP, (f) truncated/malformed variants (SRH claiming more segments than fit; option len past end).
- **GATE 0:** new fixtures compile and a throwaway test prints their bytes; existing suite still 100% green.

### Phase 1 — The cursor primitive (`tlv.hpp`), standalone
- **Do:** Add `nanotins/include/nanotins/tlv.hpp` (§3.2). Add `tests/test_tlv_cursor.cpp` + a CMake target
  (`nanotins_tlv_cursor`, label `smoke`).
- **Tests:** empty region; single Pad1; PadN; mixed options; an option whose `len` runs past `end`
  (must stop, never read OOB); `tlv_count` matches the number `next()` yields; `repeat_at` bounds (valid
  indices return in-range pointers, out-of-range returns nullptr). Include a "fuzz" loop over random byte
  buffers asserting **no read past `end`** (use an address-sanitizer build if available;
  otherwise a guarded buffer).
- **GATE 1:** `nanotins_tlv_cursor` passes, including the OOB/fuzz cases. The cursor is `NANOTINS_HD`,
  POD, and uses no STL/alloc (grep the file to confirm).

### Phase 2 — Ext-header **chain walk** + L4 correctness fix (no child tables yet)
- **Do:** Add the ext-header `WireSpec`s to `protocol_specs.hpp`; add nodes `Ipv6HopByHopNode`,
  `Ipv6RoutingNode`, `Ipv6FragmentNode`, `Ipv6DestOptNode`, `Ipv6AhNode` to `spec_dag.hpp` with correct
  `advance` (§2.1) and `next = ip6_next_dispatch`. Repoint `Ipv6Node::next` to `ip6_next_dispatch`. Add the
  nodes to `L2L3Graph`. This produces fixed per-header tables (`ipv6_ext`-style: one row per ext node) and,
  crucially, makes the walk reach the **correct** TCP/UDP node and payload offset.
- **Tests:** `tests/test_ipv6_ext_walk.cpp`: for fixtures (a)-(e), assert the walk visits the expected node
  sequence, the reported `consumed`/L4 offset is correct, and TCP/UDP rows now appear (regression: today
  they do not for (b)-(e)). Add a **parity** check: the DAG's L4 offset == a hand-computed expected value
  per fixture.
- **GATE 2:** L4 now decodes on all ext-bearing fixtures; node sequence + offsets exact; **full suite green
  (no regression to existing eth/ipv4/ipv6/tcp/udp tables)**. Confirm `serial == bulk` for the new fixed
  tables (run the bulk path on the fixtures and diff vs serial).

### Phase 3 — SRH fixed table + Fragment table
- **Do:** Give `Ipv6RoutingNode` the `Ipv6SrhSpec` so it emits the `ipv6_srh` fixed columns
  (segments_left, last_entry, flags, tag, and `num_segments = last_entry + 1`). Add the `ipv6_fragment`
  columns to `Ipv6FragmentNode`. (Still no segment/TLV child rows.)
- **Tests:** assert `ipv6_srh` rows carry correct `segments_left`/`last_entry`/`tag`/`num_segments`;
  `ipv6_fragment` carries correct `frag_offset`/`more_fragments`/`identification`.
- **GATE 3:** SRH/Fragment fixed fields exact vs fixtures; `serial == bulk`; full suite green.

### Phase 4 — Child tables: serial path (the `SRv6TlvIterator` payoff)
- **Do:** Implement the **child-record emission** for the variable data, serial first:
  - `ipv6_srh_segment`: one row per segment, using `repeat_at(base+8, num_segments, 16, srh_end, i)` →
    `fixed_size_binary(16)` address column, keyed by `packet_id` + `srh_order` + `segment_index`.
  - `ipv6_opt`: one row per option in Hop-by-Hop/Dest-Opts, using `tlv_cursor` over the option region.
  - Mechanism: extend `dag_decode.hpp` (serial `dag_decode_packet`) so a node may emit **child rows** into
    auxiliary tables via the cursor (a node-level "child sink" callback invoked during the visit). Keep all
    cursor work `NANOTINS_HD`; the table growth (`push_back`) is host-only, exactly as the existing
    `PduColumn::add`.
- **Tests:** `tests/test_ipv6_srh_segments.cpp` + `tests/test_ipv6_options.cpp`: segment addresses match
  the fixtures byte-for-byte (incl. reverse order semantics); option `type`/`len` match; malformed fixtures
  (f) yield **no OOB** and a sane truncated row count (define + assert the exact truncation policy).
- **GATE 4:** segment/option child tables exact vs fixtures and bounds-safe on malformed input; full suite
  green. (Bulk not required yet — that's Phase 5.)

### Phase 5 — Child tables: bulk path + determinism (GPU-readiness)
- **Do:** Bring the child tables into the bulk machinery in `dag_bulk.hpp` using the **same
  count → exclusive-scan → scatter** pattern as PDU nodes: a `tlv_count`/segment-count pass per packet,
  a prefix-sum into per-child-table bases, then a scatter that re-runs the cursor writing each child row to
  its prefix-summed slot. The child sink must be a **POD of raw pointers** (like `dag_sink`), captured by
  value — no STL in the kernel.
- **Tests:** extend the existing `dag_bulk` equivalence test to cover the child tables:
  **`serial == bulk`, bit-for-bit**, on all IPv6 fixtures + a large randomized batch (≥100k packets mixing
  all ext shapes).
- **GATE 5 (device-readiness checklist — all must hold):**
  - `serial == bulk` bit-identical for every new table on the randomized batch.
  - `grep -nE "std::(span|optional|vector|string)|throw|new |malloc" tlv.hpp` and the new `NANOTINS_HD`
    code paths return **nothing** in device code.
  - new cursor/sink types are `static_assert(std::is_trivially_copyable_v<…>)`.
  - all new walk/cursor loops are bounded (`kMaxWalkSteps`, region `end`).
  - the code compiles clean under `-std=c++20 -Wall -Wextra` on g++ and clang.
  - *(If a CUDA box is available)* the new headers compile under `clang -x cuda -std=c++20` behind
    `NANOTINS_ENABLE_CUDA` without host-only-symbol errors. *(If not, this sub-item is deferred but the
    grep + trivially-copyable + bounded-loop checks are mandatory.)*

### Phase 6 — Surface in the example + tshark golden (cross-repo, nanolance)
> This phase is in the **nanolance** repo (the `pcapng2lance` example owns Lance writing + the tshark
> oracle). Coordinate the submodule bump.
- **Do:** In `examples/pcapng2lance`: write the new tables in `dag_table_writer.hpp` / the driver's
  `write_pdu_tables`; teach `nlance2table` to dump them. Add a tshark cross-check
  (`test_nlance2table_tshark_ipv6_srv6.py`) on a **real** SRv6/IPv6-ext capture (obtain or craft one;
  document its provenance), comparing `ipv6_ext` / `ipv6_srh` / `ipv6_srh_segment` / `ipv6_opt` against
  tshark's `ipv6.exthdr` / `ipv6.routing.srh.*` / `ipv6.opt.*` fields.
- **GATE 6:** field-for-field agreement with tshark on the real capture (skips 77 if tshark absent, like the
  other interop tests); the existing tshark IPv4/PTP cross-checks still pass.

---

## 5. Test matrix (summary)

| Concern | Where | Gate |
|---|---|---|
| Cursor correctness + OOB safety | `test_tlv_cursor` | 1 |
| Chain walk + L4 fix | `test_ipv6_ext_walk` | 2 |
| SRH/Fragment fixed fields | (extend ext-walk test) | 3 |
| Segment/option child tables (serial) | `test_ipv6_srh_segments`, `test_ipv6_options` | 4 |
| serial == bulk (all new tables) | extend `dag_bulk` test | 5 |
| Device-safety (grep + trivially_copyable + bounded + optional CUDA compile) | checklist | 5 |
| tshark field parity on real capture | nanolance `test_nlance2table_tshark_ipv6_srv6.py` | 6 |
| No regression | full `ctest -L smoke` | every phase |

---

## 6. Files touched / added

**nanotins (this repo):**
- `nanotins/include/nanotins/tlv.hpp` *(new)* — the cursor primitive.
- `nanotins/include/nanotins/protocol_specs.hpp` — ext-header `WireSpec`s.
- `nanotins/include/nanotins/spec_dag.hpp` — new nodes, `ip6_next_dispatch`, `L2L3Graph` update,
  `Ipv6Node::next` repoint.
- `nanotins/include/nanotins/dag_decode.hpp` — child-table types + serial child emission (Phase 4).
- `nanotins/include/nanotins/dag_bulk.hpp` — child-table count/scan/scatter (Phase 5).
- `nanotins/tests/` — `test_tlv_cursor.cpp`, `test_ipv6_ext_walk.cpp`, `test_ipv6_srh_segments.cpp`,
  `test_ipv6_options.cpp`; extend `test_dag_bulk.cpp`; add fixtures to `pcap_fixtures.hpp`.
- `nanotins/CMakeLists.txt` — register the new test targets (label `smoke`).

**nanolance (separate repo, Phase 6 only):** `examples/pcapng2lance` table writer + `nlance2table` + the new
tshark test; then bump the `extern/nanotins` submodule pin.

---

## 7. Sequencing, commits, risk

- One commit per phase (Phases 0–5 in nanotins; Phase 6 in nanolance). Each commit must leave the suite
  green. Do **not** bundle phases.
- **Stop-the-line:** if any gate cannot be made green, stop and report — do not proceed or weaken the gate.
- **Highest-value early exit:** Phases 1–3 already deliver the **L4 correctness fix** + ext-header/SRH
  fixed tables with the least machinery. If time is short, ship through Phase 3, then Phase 4/5 later — they
  are additive. (The segment/option child tables are the headline but the hardest; isolate them.)
- **Risk areas:** (1) the child-emission mechanism in `dag_decode`/`dag_bulk` is the one place you extend
  the engine — keep it a strict mirror of the existing PDU count/scan/scatter; (2) length-rule edge cases
  (Fragment fixed 8, AH 4-byte units, ESP/No-Next terminators) — table-drive them and unit-test each; (3)
  malformed-packet bounds — every variable read goes through the validated cursor / `repeat_at`.

---

## 8. Definition of done

Correct L4 on IPv6+extension packets; `ipv6_ext` / `ipv6_srh` / `ipv6_srh_segment` / `ipv6_opt` /
`ipv6_fragment` tables populated correctly and bounds-safe; `serial == bulk` bit-identical; device-safety
checklist satisfied (GPU transition preserved); tshark field-parity on a real SRv6 capture; zero regressions
to existing tables/tests; all new code C++20 + `NANOTINS_HD`-clean.
