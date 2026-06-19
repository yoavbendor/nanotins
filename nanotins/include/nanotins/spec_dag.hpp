// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// A declarative, device-safe DAG/FSM for protocol dispatch — the spec-driven replacement for the
// hand-written walk_packet switch (protocol_decode.hpp). The traversal it encodes is identical:
//
//     Ethernet --ethertype--> { VlanTag (self-loop on QinQ) | IPv4 | IPv6 | gPTP }
//     IPv4     --protocol (gated by frag_offset==0)--> { TCP | UDP }
//     IPv6     --next_header--> { TCP | UDP }
//
// but expressed as a graph of nodes instead of nested branches. A node binds a wire_spec (the header at
// the current offset) to two pure functions: advance(p) (header length consumed) and next<Graph>(p) (read
// a discriminator field, look it up in a compile-time edge table, return the target node id or -1=stop).
//
// Design constraints (settled earlier):
//   * Two faces, one source. The walk is NANOTINS_HD: no STL, no allocation, no virtuals — the same loop
//     runs host-contiguous and inside a GPU bulk kernel. The visitor recovers the compile-time node/spec.
//   * Reject heuristics. Dispatch is an exact-key edge table (linear-scanned, device-safe). No ambiguity:
//     a key matches at most one edge, so CPU == GPU == bulk by construction.
//   * Additive. A new protocol is a new node struct + one edge row in its parent's table. Sibling nodes
//     and the engine are untouched; that is the whole point of moving dispatch out of one big switch.
//
// This is the framing/dispatch layer only. Stateful frame assembly (PTP correlation, sensor reassembly)
// and numeric reconstruction live above it.

#include "nanotins/protocol_specs.hpp"
#include "nanotins/protocol_specs_ptp.hpp"
#include "nanotins/protocol_specs_someip.hpp"
#include "nanotins/wire_spec.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>

namespace nanotins {

using namespace literals;

// ---- graph + node-id resolution ----------------------------------------------------------------------
// A graph is just the (ordered) set of node types; a node's id is its index in the set.
template <class... Nodes>
struct graph {
    static constexpr std::size_t size = sizeof...(Nodes);
    using nodes = std::tuple<Nodes...>;
};

namespace detail_dag {
template <class T, class Tuple>
struct index_of;
template <class T, class... Ts>
struct index_of<T, std::tuple<T, Ts...>> : std::integral_constant<std::size_t, 0> {};
template <class T, class U, class... Ts>
struct index_of<T, std::tuple<U, Ts...>>
    : std::integral_constant<std::size_t, 1 + index_of<T, std::tuple<Ts...>>::value> {};
}  // namespace detail_dag

template <class Node, class Graph>
inline constexpr int node_id_v = static_cast<int>(detail_dag::index_of<Node, typename Graph::nodes>::value);

// ---- edges: the additive dispatch table --------------------------------------------------------------
// An edge maps an exact discriminator key to a target node *type* (resolved to an id against the graph at
// the walk site, so nodes reference each other by type and stay index-agnostic).
template <std::uint64_t Key, class TargetNode>
struct edge {
    static constexpr std::uint64_t key = Key;
    using target = TargetNode;
};

// Linear-scan the edge table for an exact key match; return the target node id or -1 (stop). Keys are
// unique per table (a heuristic-free, order-independent match), so the fold visits at most one hit.
template <class Graph, class... Edges>
NANOTINS_HD inline int match_edges(std::uint64_t key) noexcept {
    int target = -1;
    ((key == Edges::key ? (target = node_id_v<typename Edges::target, Graph>) : 0), ...);
    return target;
}

// A key that no u8/u16 discriminator can take — used to force a stop (e.g. an IPv4 fragment has no L4).
inline constexpr std::uint64_t kNoDispatch = 0xFFFF'FFFF'FFFF'FFFFull;

// ---- the walk ----------------------------------------------------------------------------------------
struct walk_result {
    std::size_t consumed = 0;  // total header bytes walked (offset of the first un-parsed byte)
    int steps = 0;             // nodes visited
};

// Max nodes per packet — bounds the device loop and guards malformed self-loops (a corrupt QinQ chain).
inline constexpr int kMaxWalkSteps = 32;

namespace detail_dag {
// Resolve a runtime node id to its compile-time node type via an unrolled if-chain, then: fit-check the
// spec, invoke the visitor with the node's static index + offset, and read advance/next from the node.
template <class Graph, std::size_t I, class Visit>
NANOTINS_HD inline bool dispatch_node(int id, const std::uint8_t* p, std::size_t off, std::size_t size,
                                      Visit& visit, int& next_id, std::size_t& adv) noexcept {
    if constexpr (I < Graph::size) {
        if (id == static_cast<int>(I)) {
            using N = std::tuple_element_t<I, typename Graph::nodes>;
            if (off + spec_size<typename N::spec>() > size) {
                return false;  // header does not fit — stop, as walk_packet does on a short read
            }
            visit(std::integral_constant<std::size_t, I>{}, off);
            adv = N::advance(p + off);
            next_id = N::template next<Graph>(p + off);
            return true;
        }
        return dispatch_node<Graph, I + 1>(id, p, off, size, visit, next_id, adv);
    } else {
        (void)id;
        (void)p;
        (void)off;
        (void)size;
        (void)visit;
        (void)next_id;
        (void)adv;
        return false;
    }
}
}  // namespace detail_dag

// Walk a packet from `root` node id, calling visit(integral_constant<I>, offset) for each emitted PDU in
// order. Device-safe: bounded loop, no allocation, the visitor carries any state. Returns where parsing
// stopped (the application-payload boundary / remainder offset).
template <class Graph, class Visit>
NANOTINS_HD inline walk_result walk(int root, const std::uint8_t* p, std::size_t size, Visit visit) noexcept {
    walk_result r;
    int node = root;
    std::size_t off = 0;
    for (int step = 0; step < kMaxWalkSteps && node >= 0; ++step) {
        int next_id = -1;
        std::size_t adv = 0;
        if (!detail_dag::dispatch_node<Graph, 0>(node, p, off, size, visit, next_id, adv)) {
            break;
        }
        off += adv;
        r.consumed = off;
        ++r.steps;
        node = next_id;
    }
    return r;
}

// ---- the L2/L3/L4 nodes ------------------------------------------------------------------------------
// Forward declarations so each node's edge table can name its siblings/targets by type.
struct EthNode;
struct VlanNode;
struct Ipv4Node;
struct Ipv6Node;
struct TcpNode;
struct UdpNode;
struct GptpNode;
struct PtpTimestampBody;  // Sync / Follow_Up / Delay_Req / Pdelay_Req body
struct PtpTsPortBody;     // Delay_Resp / Pdelay_Resp / Pdelay_Resp_Follow_Up body
struct PtpAnnounceBody;   // Announce body
struct PtpSignalingBody;  // Signaling body
struct Ipv6HopByHopNode;  // IPv6 Hop-by-Hop Options ext header (next_header 0)
struct Ipv6RoutingNode;   // IPv6 Routing ext header / SRv6 SRH (next_header 43)
struct Ipv6FragmentNode;  // IPv6 Fragment ext header (next_header 44)
struct Ipv6DestOptNode;   // IPv6 Destination Options ext header (next_header 60)
struct Ipv6AhNode;        // IPv6 Authentication Header (next_header 51)
struct SomeipNode;        // SOME/IP message header (over UDP/TCP, dispatched by well-known port)

// The post-L2 EtherType dispatch is identical for Ethernet and a VLAN tag's inner type, so both share it.
template <class Graph>
NANOTINS_HD inline int ethertype_dispatch(std::uint16_t et) noexcept {
    return match_edges<Graph, edge<0x8100, VlanNode>, edge<0x88A8, VlanNode>, edge<0x0800, Ipv4Node>,
                       edge<0x86DD, Ipv6Node>, edge<0x88F7, GptpNode>>(et);
}

// IPv4 dispatches the L4 on an 8-bit protocol number to the TCP/UDP targets.
template <class Graph>
NANOTINS_HD inline int ip_proto_dispatch(std::uint64_t proto) noexcept {
    return match_edges<Graph, edge<6, TcpNode>, edge<17, UdpNode>>(proto);
}

// IPv6 dispatches its `next_header` byte — used by the base IPv6 header AND by every extension header — to
// the next extension header in the chain or to L4. Extension-header types (0 Hop-by-Hop, 43 Routing/SRv6,
// 44 Fragment, 60 Destination Options, 51 AH) route to their nodes; 6/17 are L4; everything else (50 ESP,
// 59 No-Next, and unknown upper-layer protocols) returns -1 to stop the walk. The graph therefore cycles
// through the ext nodes until L4/terminator (bounded by kMaxWalkSteps).
template <class Graph>
NANOTINS_HD inline int ip6_next_dispatch(std::uint64_t next_header) noexcept {
    return match_edges<Graph, edge<0, Ipv6HopByHopNode>, edge<43, Ipv6RoutingNode>,
                       edge<44, Ipv6FragmentNode>, edge<60, Ipv6DestOptNode>, edge<51, Ipv6AhNode>,
                       edge<6, TcpNode>, edge<17, UdpNode>>(next_header);
}

struct EthNode {
    using spec = EthernetSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return 14; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        return ethertype_dispatch<G>(struct_view<EthernetSpec>(p)("ethertype"_fld));
    }
};

struct VlanNode {
    using spec = VlanTagSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return 4; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        // self-loop on a stacked tag (QinQ); otherwise dispatch the inner EtherType like Ethernet does.
        return ethertype_dispatch<G>(struct_view<VlanTagSpec>(p)("inner_ethertype"_fld));
    }
};

struct Ipv4Node {
    using spec = Ipv4Spec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        const std::size_t hdr = static_cast<std::size_t>(struct_view<Ipv4Spec>(p)("ihl"_fld)) * 4u;
        return hdr >= 20 ? hdr : 20;  // skip options; never less than the fixed header
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        struct_view<Ipv4Spec> v(p);
        // A non-zero fragment offset means the remainder is fragment data, not an L4 header — stop here
        // (matches walk_packet's L4 gate / tshark, which shows L4 only on the first fragment).
        if (v("frag_offset"_fld) != 0) {
            return -1;
        }
        return ip_proto_dispatch<G>(v("protocol"_fld));
    }
};

struct Ipv6Node {
    using spec = Ipv6Spec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return 40; }  // fixed base header
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        // Walk the extension-header chain: next_header may be an ext header (Hop-by-Hop, Routing/SRv6,
        // Fragment, Dest-Opts, AH) or an L4 protocol. ip6_next_dispatch routes both.
        return ip6_next_dispatch<G>(struct_view<Ipv6Spec>(p)("next_header"_fld));
    }
};

// ---- IPv6 extension-header nodes -------------------------------------------------------------------
// Each emits its fixed-field row (a per-type table) and continues the chain by dispatching on its OWN
// next_header byte. advance() returns the WHOLE header length (incl. any variable segment list / options),
// so the chain reaches the correct L4 offset even though only the fixed fields are emitted here. The
// variable parts (SRH segments + TLVs, Hop-by-Hop / Dest-Opt options) are decoded into child tables
// separately (see dag_decode child emission).

// Hop-by-Hop and Destination Options: same 2-byte preamble, length (hdr_ext_len + 1) * 8.
struct Ipv6HopByHopNode {
    using spec = Ipv6ExtOptSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        return (static_cast<std::size_t>(struct_view<Ipv6ExtOptSpec>(p)("hdr_ext_len"_fld)) + 1u) * 8u;
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        return ip6_next_dispatch<G>(struct_view<Ipv6ExtOptSpec>(p)("next_header"_fld));
    }
};
struct Ipv6DestOptNode {
    using spec = Ipv6ExtOptSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        return (static_cast<std::size_t>(struct_view<Ipv6ExtOptSpec>(p)("hdr_ext_len"_fld)) + 1u) * 8u;
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        return ip6_next_dispatch<G>(struct_view<Ipv6ExtOptSpec>(p)("next_header"_fld));
    }
};

// Routing header / SRv6 SRH: length (hdr_ext_len + 1) * 8.
struct Ipv6RoutingNode {
    using spec = Ipv6SrhSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        return (static_cast<std::size_t>(struct_view<Ipv6SrhSpec>(p)("hdr_ext_len"_fld)) + 1u) * 8u;
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        return ip6_next_dispatch<G>(struct_view<Ipv6SrhSpec>(p)("next_header"_fld));
    }
};

// Fragment header: fixed 8 bytes.
struct Ipv6FragmentNode {
    using spec = Ipv6FragmentSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return 8; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        struct_view<Ipv6FragmentSpec> v(p);
        // Only the first fragment (offset 0) carries the L4 header; a continuation fragment (offset != 0)
        // is fragment payload data, so dispatching L4 there would overlay garbage. Stop instead — mirrors
        // the IPv4 fragmentation gate (Ipv4Node) and tshark's "L4 only on the first fragment". The fragment
        // row itself is still emitted (the visit happened before next()).
        if (v("frag_offset"_fld) != 0) {
            return -1;
        }
        return ip6_next_dispatch<G>(v("next_header"_fld));
    }
};

// Authentication Header: length (payload_len + 2) * 4.
struct Ipv6AhNode {
    using spec = Ipv6AhSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        return (static_cast<std::size_t>(struct_view<Ipv6AhSpec>(p)("payload_len"_fld)) + 2u) * 4u;
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        return ip6_next_dispatch<G>(struct_view<Ipv6AhSpec>(p)("next_header"_fld));
    }
};

// L4 -> SOME/IP dispatch: a SOME/IP message rides UDP/TCP on a well-known port. Ports are an exact key
// (no heuristic), so this stays in the match_edges model — but unlike EtherType, service ports are dynamic,
// so we match the canonical SD port on EITHER endpoint and leave additional ports as extra edge rows added
// by configuration. Returns the SomeipNode id on a hit, else -1 (the L4 stays a leaf).
template <class Graph>
NANOTINS_HD inline int someip_port_dispatch(std::uint16_t dst, std::uint16_t src) noexcept {
    const int t = match_edges<Graph, edge<kSomeipSdPort, SomeipNode>>(dst);
    return t >= 0 ? t : match_edges<Graph, edge<kSomeipSdPort, SomeipNode>>(src);
}

struct TcpNode {
    using spec = TcpSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t* p) noexcept {
        const std::size_t hdr = static_cast<std::size_t>(struct_view<TcpSpec>(p)("data_offset"_fld)) * 4u;
        return hdr >= 20 ? hdr : 20;
    }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        struct_view<TcpSpec> v(p);
        return someip_port_dispatch<G>(v("dst_port"_fld), v("src_port"_fld));  // else -1 (payload)
    }
};

struct UdpNode {
    using spec = UdpSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return 8; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        struct_view<UdpSpec> v(p);
        return someip_port_dispatch<G>(v("dst_port"_fld), v("src_port"_fld));  // else -1 (payload)
    }
};

// Nested dispatch: a gPTP message's body is selected by the common header's message_type:4 field. Bodies
// are grouped by wire shape (the gptp table's message_type column disambiguates which message a row is).
template <class Graph>
NANOTINS_HD inline int ptp_msgtype_dispatch(std::uint64_t mt) noexcept {
    return match_edges<Graph,
                       edge<kPtpMsgSync, PtpTimestampBody>, edge<kPtpMsgFollowUp, PtpTimestampBody>,
                       edge<kPtpMsgDelayReq, PtpTimestampBody>, edge<kPtpMsgPdelayReq, PtpTimestampBody>,
                       edge<kPtpMsgDelayResp, PtpTsPortBody>, edge<kPtpMsgPdelayResp, PtpTsPortBody>,
                       edge<kPtpMsgPdelayRespFollowUp, PtpTsPortBody>, edge<kPtpMsgAnnounce, PtpAnnounceBody>,
                       edge<kPtpMsgSignaling, PtpSignalingBody>>(mt);
}

struct GptpNode {
    using spec = PtpHeaderSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return kPtpHeaderLen; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t* p) noexcept {
        // emit the common header, then sub-dispatch into the per-message body at byte kPtpHeaderLen.
        return ptp_msgtype_dispatch<G>(struct_view<PtpHeaderSpec>(p)("message_type"_fld));
    }
};

// The gPTP body nodes — each emits its body spec at the post-header offset, then stops (leaf). advance is
// the spec's fixed extent (the body's wire size).
struct PtpTimestampBody {
    using spec = PtpTimestampBodySpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return spec_size<PtpTimestampBodySpec>(); }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t*) noexcept { return -1; }
};
struct PtpTsPortBody {
    using spec = PtpTsPortBodySpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return spec_size<PtpTsPortBodySpec>(); }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t*) noexcept { return -1; }
};
struct PtpAnnounceBody {
    using spec = PtpAnnounceBodySpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return spec_size<PtpAnnounceBodySpec>(); }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t*) noexcept { return -1; }
};
struct PtpSignalingBody {
    using spec = PtpSignalingBodySpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return spec_size<PtpSignalingBodySpec>(); }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t*) noexcept { return -1; }
};

// ---- SOME/IP -----------------------------------------------------------------------------------------
// Emits the fixed 16-byte SOME/IP message header at the post-L4 offset, then stops (leaf). The variable
// payload — flat-serialized RPC args, SOME/IP-SD entries/options, or TLV members — is decoded in later
// phases (SD child tables, a someip_tlv_cursor); none of it is needed to tabulate the header. advance() is
// the fixed header size, so the walk's `consumed` lands at the payload boundary.
struct SomeipNode {
    using spec = SomeipSpec;
    static NANOTINS_HD std::size_t advance(const std::uint8_t*) noexcept { return kSomeipHeaderLen; }
    template <class G>
    static NANOTINS_HD int next(const std::uint8_t*) noexcept { return -1; }
};

// The full L2/L3/L4 + gPTP graph. EthNode is the root (id 0). Adding a protocol appends a node here and one
// edge row in its parent's dispatch — nothing else changes. The gPTP message-type bodies are the newest
// additions (GptpNode -> {timestamp | ts+port | announce | signaling}).
// The IPv6 extension-header nodes are appended at the end so existing node ids / table positions are
// unchanged (additive). The graph now cycles through ext nodes on the IPv6 branch until it reaches L4.
// SomeipNode is appended last (additive): existing node ids / table positions are unchanged, and UDP/TCP
// now reach it on the well-known SOME/IP port (a leaf otherwise, exactly as before).
using L2L3Graph = graph<EthNode, VlanNode, Ipv4Node, Ipv6Node, TcpNode, UdpNode, GptpNode, PtpTimestampBody,
                        PtpTsPortBody, PtpAnnounceBody, PtpSignalingBody, Ipv6HopByHopNode, Ipv6RoutingNode,
                        Ipv6FragmentNode, Ipv6DestOptNode, Ipv6AhNode, SomeipNode>;

inline constexpr int kEthRoot = node_id_v<EthNode, L2L3Graph>;

}  // namespace nanotins
