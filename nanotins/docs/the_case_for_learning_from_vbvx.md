<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Yoav Bendor -->

# The case for learning from vbvx

A design note on three ideas worth borrowing from
[**vbvx**](https://github.com/llmxio/vbvx) (a C++23, header-only, zero-copy packet-view library), and a
deep dive on the most valuable one: **variable-length / TLV parsing**, why it matters for **IPv6 extension
headers and SRv6**, and how adopting vbvx's `SRv6TlvIterator` *pattern* both fixes a real correctness gap in
nanotins and unlocks a whole class of protocols — all while preserving Arrow compatibility.

> **TL;DR.** nanotins today assumes an IPv6 packet is a fixed 40-byte header immediately followed by L4.
> That is wrong for any IPv6 packet carrying **extension headers** (Hop-by-Hop, Routing/SRv6, Fragment,
> Destination Options, …): we mis-read the L4 protocol, compute the wrong payload offset, and cannot expose
> the data those headers carry (e.g. an SRv6 segment list). vbvx shows a clean, allocation-free,
> bounds-checked cursor for exactly this shape of data. Generalising that cursor into a `repeat<>`/`tlv<>`
> element — emitting Arrow **`List<…>`** columns — is the single highest-value thing we can take from vbvx.

---

## 1. What vbvx is (and isn't)

vbvx = "VPP Buffer View eXtensions": header-only **C++23**, zero-copy, bounds-checked *views* over wire
headers (Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP **and SRv6**), aimed at inspection/editing in a
VPP-style dataplane. It is **narrower** than nanotins — it has no SoA, no Arrow, no declarative spec, no
DAG, no bulk/GPU path. It stops where nanotins' interesting half begins (columns + tables).

So this is not "catch up to a competitor". It is "mine a focused library for a few good ideas". Three are
worth adopting; all are additive and **Arrow-preserving**:

| # | Idea from vbvx | What we gain | Arrow impact |
|---|---|---|---|
| 1 | **Typed bitmask flag views** (`FlagsView` / `enable_bitmask_operators`) | `tcp.flags().has(SYN)` instead of bit math; optional fan-out into named boolean columns | none — underlying integer column is unchanged |
| 2 | **Variable-length / TLV parsing** (`SRv6TlvIterator`, segment lists) | IPv6 extension-header chains, SRv6, TCP/DHCP options; **fixes an L4 correctness gap** | **new** — native Arrow `List<…>` columns |
| 3 | **A real error model** (`std::optional` / `std::expected` returns) | host-side parse APIs return values, not `bool` + out-param | none — host-only ergonomics |

This note focuses on **#2**, because it is both the highest value and the least obvious. (#1 and #3 are
small and self-explanatory; see §7.)

---

## 2. Background: IPv4 "options" vs IPv6 "extension headers"

To understand why #2 matters, you need to understand a deliberate design change between IPv4 and IPv6.

### IPv4: a variable-length *options* field, inline

An IPv4 header is 20 bytes **plus** up to 40 bytes of optional **options**, all in one header. The `IHL`
("Internet Header Length") field gives the true header length in 32-bit words, so the real L4 starts at
`IHL * 4` bytes. nanotins already handles this — see `decode_l3`, which computes
`hdr = (ver_ihl & 0x0F) * 4` and skips IPv4 options. Options are rare in practice and were considered a
performance problem (routers had to parse variable headers on the fast path).

### IPv6: a *chain* of extension headers, daisy-linked

IPv6 fixed the "variable header on the fast path" problem by making the **base header a fixed 40 bytes**
with **no options field**. Anything optional moves into separate **extension headers** placed *between* the
base IPv6 header and the upper-layer (L4) payload. They form a **linked chain**: every header — the base
header and each extension header — carries an 8-bit **`Next Header`** field that names what comes next.
`Next Header` is either *another extension header type* or an *upper-layer protocol number*:

```
+-----------------+   next=43   +------------------+   next=60  +----------------------+  next=6  +--------+
| IPv6 base hdr   | ----------> | Routing (SRv6)   | ---------> | Destination Options  | -------> |  TCP   |
| next_header=43  |             | next_header=60   |            | next_header=6        |          |  ...   |
| (40 bytes)      |             | (variable)       |            | (variable, TLVs)     |          |        |
+-----------------+             +------------------+            +----------------------+          +--------+
        ^                                                                                            ^
   fixed length                              you MUST walk the chain                          real L4 starts here
```

The set of `Next Header` values that mean "another extension header" (vs an upper-layer protocol):

| Next Header | Meaning | Length rule |
|---|---|---|
| 0   | Hop-by-Hop Options | `(Hdr Ext Len + 1) * 8` bytes; **TLV** body |
| 43  | Routing (Routing Type 4 = **SRv6 SRH**) | `(Hdr Ext Len + 1) * 8`; segment list + TLVs |
| 44  | Fragment | fixed **8** bytes |
| 60  | Destination Options | `(Hdr Ext Len + 1) * 8`; **TLV** body |
| 51  | Authentication Header (AH) | `(Payload Len + 2) * 4` bytes |
| 50  | ESP (encrypted) | opaque — chain ends for plaintext inspection |
| 59  | No Next Header | chain ends |
| 6 / 17 / 58 / … | TCP / UDP / ICMPv6 / … (upper layer) | not an extension header — this is L4 |

The crucial consequence:

> **You cannot find L4 in an IPv6 packet by looking at a fixed offset. You must walk the `Next Header`
> chain, adding each extension header's length, until you reach an upper-layer protocol number.**

Most extension headers share a common 2-byte preamble — `[Next Header][Hdr Ext Len]` — where `Hdr Ext Len`
is measured in 8-byte units *not counting the first 8 bytes*, so the header is `(Hdr Ext Len + 1) * 8`
bytes. (Fragment is a fixed 8 bytes; AH uses 4-byte units; ESP is encrypted.) That regular preamble is
what makes a *generic* chain-walker possible.

### TLV options *inside* Hop-by-Hop and Destination Options

Hop-by-Hop and Destination Options headers carry a list of **TLV options**, each:

```
[ Option Type : 1 byte ][ Opt Data Len : 1 byte ][ Option Data : Opt Data Len bytes ]
```

with two padding specials:

- **Pad1** — Option Type `0`, a *single byte*, no length/value (the one exception to the TLV shape).
- **PadN** — Option Type `1`, then `Opt Data Len`, then that many zero bytes.

The high bits of the Option Type are themselves meaningful (what a node must do if it doesn't recognise the
option; whether the option may change in transit). This `[type][len][value]` + `Pad1` shape is **exactly**
what vbvx's `SRv6TlvIterator` walks.

---

## 3. SRv6 in one page (and why anyone cares)

**Segment Routing over IPv6 (SRv6)** encodes a *source-chosen path* — a list of "segments" (waypoints or
functions) — directly in the packet, using a **Routing extension header** (`Next Header = 43`) with
**Routing Type = 4**, called the **Segment Routing Header (SRH)**:

```
 0               1               2               3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   | Hdr Ext Len   | Routing Type=4| Segments Left |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Last Entry    |     Flags     |              Tag              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|            Segment List[0]  (128-bit IPv6 address)            |   <-- 16 bytes
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
|            Segment List[n]  (128-bit IPv6 address)            |   <-- 16 bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Optional TLVs (HMAC, PadN, …)            |   <-- [type][len][value], Pad1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Segment List** — an array of full 128-bit IPv6 addresses, stored in **reverse** order (`Segment
  List[0]` is the *last* segment). Its length is variable and bounded by `Hdr Ext Len`; the number of
  entries is `Last Entry + 1`.
- **Segments Left** — pointer (countdown) into the list as the packet is forwarded.
- **TLVs** — optional trailing records (e.g. an **HMAC** TLV for integrity), in the same `[type][len][value]`
  + `Pad1` shape as IPv6 options.

Why it is worth supporting: SRv6 is the successor to SR-MPLS for **traffic engineering, service chaining
(SFC), VPNs, and 5G transport**, deployed by large carriers and hyperscalers. A packet's segment list is a
high-signal telemetry artifact: it literally records the intended path/functions. For a capture-to-columns
tool like nanolance, "give me a table of every SRv6 segment list seen, by packet" is precisely the kind of
question users will ask — and today we cannot even *reach L4* on these packets, let alone surface the list.

---

## 4. What nanotins does today — the gap (and the silent bug)

nanotins' L3 step treats IPv6 as a fixed 40-byte header and reads its `next_header` **as if it were the L4
protocol**. From `protocol_decode.hpp`:

```cpp
} else if (ethertype == kEtherTypeIpv6) {
    Ipv6 ip{};
    if (!overlay(after_l2, 0, ip)) return res;
    on_ipv6(ip);
    l3 = sizeof(Ipv6);          // <-- assumes NO extension headers
    ip_proto = ip.next_header;  // <-- treats next_header as the L4 proto
}
```

Consequences when extension headers *are* present:

1. **Correctness.** If `next_header` is `43` (Routing/SRv6), `0` (Hop-by-Hop), `44` (Fragment), `60`
   (Dest-Opts), … we treat that number as an "IP protocol", match neither TCP (6) nor UDP (17), and **emit
   no L4** — even though a perfectly good TCP/UDP header sits a few bytes further on. The computed
   L4-payload boundary (the `remainder_after_l4`) is also wrong. This is silent: no crash, just missing /
   misplaced rows.
2. **Coverage.** We cannot expose anything the extension headers carry — no SRv6 segment list, no
   Hop-by-Hop/Dest-Opts options, no fragment info. That data is invisible to the columns.

This is not hypothetical for IPv6-heavy captures (mobile cores, ISP backbones, data-center underlays,
anything touching SRv6).

---

## 5. What vbvx demonstrates: a generic, allocation-free TLV/segment cursor

vbvx's SRv6 support is the part most relevant to us. Two reusable shapes:

- **A fixed-stride repeat** — the segment list is "N records of exactly 16 bytes". vbvx exposes it as a
  bounds-checked `std::span<const uint8_t, 16> segment_at(idx)` (and a `safe_segment_at(idx, remaining)`
  returning `std::optional`).
- **A TLV cursor** — `SRv6TlvIterator` walks the trailing TLVs *statefully and without allocation*,
  handling `Pad1` (1 byte) and standard `[type][len][value]` records, stopping at the region boundary.
- **One validation gate** — `validate_srh_bounds()` checks the lengths up front (header ≥ 8 and 8-byte
  aligned, the whole SRH fits in the packet, `Last Entry`/`Segments Left` in range, TLV region within the
  header) so every accessor can then assume safety and return `std::nullopt` on the edge cases.

The lesson is **not** "vendor vbvx's SRv6 code" (it's host-only, `std::span`/`std::optional`-based, and not
columnar). The lesson is the **pattern**: a *validated, allocation-free, bounds-checked cursor over
variable-length records* — fixed-stride repeats (segment list) and `[type][len][value]` TLVs (options) —
is the missing primitive. nanotins needs that primitive in a form that (a) is `NANOTINS_HD`-safe where it
runs in the decode walk, and (b) lands in **Arrow columns**.

---

## 6. How we adopt it in nanotins — `repeat<>` / `tlv<>` → Arrow `List<…>`

Two pieces, both additive.

### 6a. Walk the extension-header chain (fixes the L4 bug)

Teach the IPv6 step to loop the `Next Header` chain instead of assuming 40 bytes:

```
start at the base IPv6 header (next = ip.next_header, off = 40)
while next is an extension-header type:
    read [next_header][hdr_ext_len] at off
    len = length_for(next, hdr_ext_len)        // (hdr_ext_len+1)*8, with Fragment=8, AH=(plen+2)*4
    emit an ext-header row (type, len, + per-type fields)
    next = this header's next_header
    off += len
ip_proto = next                                 // the TRUE L4 protocol
l4 starts at off                                // the CORRECT payload boundary
```

In DAG terms this is a node that *loops over its own kind* before handing off — the existing
count→scan→scatter bulk machinery already tolerates a **variable number of rows per packet**, so an
`ipv6_ext` table (0..N rows per packet, keyed by `packet_id`) drops in exactly like the VLAN table does
today. **This alone fixes the silent L4 mis-decode**, independent of any fancy SRv6 column.

### 6b. A `repeat<>` / `tlv<>` spec element → Arrow `List<…>`

Add two vocabulary items to `wire_spec`, mirroring vbvx's two shapes:

- `repeat<Field, CountFrom>` — N records of a fixed stride (SRv6 segment list = 16-byte records, count from
  `Last Entry + 1`). Emits an Arrow **`List<FixedSizeBinary(16)>`** column (a list of IPv6 addresses).
- `tlv<...>` — a `[type][len][value]` walk with `Pad1`/`PadN`, bounded by the enclosing header. Emits an
  Arrow **`List<Struct{ type:u8, len:u8, value:binary }>`** column (or a child table keyed by `packet_id`).

```
SRv6 SRH spec  ->  columns:  next_header:u8, hdr_ext_len:u8, routing_type:u8,
                             segments_left:u8, last_entry:u8, flags:u8, tag:u16,
                             segment_list : List<FixedSizeBinary(16)>     <-- repeat<>
                             tlvs         : List<Struct{type,len,value}>  <-- tlv<>
```

This is the first time nanotins' SoA goes beyond fixed-width + `fixed_size_binary` into **native Arrow
nested types** — and `List<…>` / `Struct<…>` are first-class in Arrow, nanoarrow, Lance, and Parquet, so
**Arrow compatibility is preserved by construction** (we're using standard Arrow, not inventing anything).
The variable-length data lives in Arrow's offsets+values buffers; the per-packet row count is unchanged.

The same `repeat<>`/`tlv<>` primitive immediately generalises beyond SRv6:

- **Hop-by-Hop / Destination Options** → `tlv<>` (the IPv6 options themselves).
- **TCP options** (MSS, SACK, timestamps, window scale) → `tlv<>`.
- **DHCP / DHCPv6 options**, **ICMPv6 ND options**, **GTP/extension headers**, etc.

One primitive, many protocols — that is the leverage.

### 6c. Device-safety and the host/device split

vbvx uses `std::span`/`std::optional` freely because it is **host-only**. nanotins deliberately does not
use `std::span` in device code (it pulls host-only assertion hooks under clang-cuda — that is why `Bytes`
exists). So:

- The **chain walk** and the **fixed-stride `repeat<>` count** stay in the `NANOTINS_HD` path (plain
  pointer arithmetic + bounds checks, like the existing `walk_packet`).
- The **`List<…>` buffer assembly** (offsets + values) is a **host** concern in the table writer — the
  same place the columnar fan-out already happens — so no `std::optional`/`std::vector` enters device code.
- Mirror vbvx's `validate_srh_bounds()` as a single up-front bounds gate per variable region, so the inner
  accessors are branch-light and safe.

---

## 7. The other two ideas (smaller, also worth doing)

- **#1 Typed bitmask flags (`flags<Enum>`).** A soatins opt-in (`enable_bitmask_operators` + a concept,
  collapsible to one class with C++23 *deducing `this`*) so consumers read `tcp.flags().has(Tcp::Flag::SYN)`
  and we can optionally fan a flags word out into named boolean columns (`syn`, `ack`, `fin`, …) for
  analytics. The stored column stays the underlying integer — **zero Arrow change**. Good first step;
  device-safe (it is just masked integer math behind a concept).
- **#3 Error model (`std::optional`/`std::expected`).** On the **host** seam (`scan_*`, `to_ndjson`, the
  drivers), return `std::expected<View, ParseError>` instead of `bool` + out-param. Host-only; do not put
  it in the `NANOTINS_HD` hot path.

### A note on C++23

vbvx is C++23; nanotins is C++20. A blanket bump is **not** recommended: the device-callable headers are
shared host+device, and a future GPU re-introduction compiles them under clang-cuda / nvcc, where **nvcc's
C++23 support is still immature** — bumping repo-wide raises the adopter compiler bar and risks the GPU
path we deliberately kept open (`NANOTINS_HD`). Instead: keep the device-safe core at **C++20**; allow
**C++23 in host-only TUs** (examples, tools, the seam) where `std::expected` and deducing-`this` actually
pay off; guard any C++23 feature that creeps into shared headers behind `__cpp_*` feature-test macros.
Revisit a full bump once nvcc C++23 matures and the GPU layer returns.

---

## 8. Suggested phasing

1. **`flags<Enum>` in soatins** + apply to TCP/IPv4/EPB/PTP flags (small, immediate, device-safe). *(idea #1)*
2. **IPv6 extension-header chain walk** — the correctness fix, as an `ipv6_ext` DAG node with a per-packet
   variable row count (no new Arrow machinery yet). *(idea #2, part 1 — highest correctness value)*
3. **`repeat<>` + Arrow `List<FixedSizeBinary(16)>`**, proven on the **SRv6 segment list**. *(idea #2, part 2)*
4. **`tlv<>` + Arrow `List<Struct>`**, proven on **IPv6 options + SRv6 TLVs**, then reused for **TCP
   options**. *(idea #2, part 3 — the big generalisation)*
5. **`std::expected` host error model** + a C++23 opt-in for the standalone/example builds. *(idea #3)*

Each step is independently shippable, additive, and Arrow-compatible. Step 2 is worth doing on its own
merit — it turns a silent IPv6 mis-decode into correct L4 — even if we never write a single SRv6 column.

---

## 9. Non-goals / what *not* to copy

- We do **not** vendor vbvx code (different license posture is fine — both Apache-2.0 — but it is host-only
  and non-columnar; the value is the *pattern*, not the source).
- We do **not** adopt its mutating `FlagsView` (`set/clear/toggle` on a live buffer) — nanotins is
  decode-only; we take the read-side (`ConstFlagsView`) shape.
- We do **not** put `std::span`/`std::optional`/`std::expected` into the `NANOTINS_HD` device path.
- We do **not** do a blanket C++23 migration (see §7).

---

*See also: [`architecture.html`](architecture.html) (wire_spec / SoA / DAG and the add-a-parser recipe) —
the `repeat<>`/`tlv<>` work extends exactly the machinery described there.*
