// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// Bulk decode of the IPv6 child tables (SRv6 segments + IPv6/SRH options), using the same
// count -> exclusive prefix-sum -> scatter pattern as dag_bulk.hpp, over the SAME NANOTINS_HD traversals
// (for_each_srh_child / for_each_opt) the serial path uses — so the bulk output is byte-identical to the
// serial output (serial == bulk == future gpu). The scatter sink is a POD of raw pointers, so a CUDA bulk
// kernel can capture it unchanged; only the host orchestration (sizing the std::vectors) lives here.

#include "nanotins/bulk.hpp"
#include "nanotins/dag_bulk.hpp"  // dag_packet
#include "nanotins/ipv6_children.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nanotins {

// Bulk-decode packets' IPv6 child records into `kids` via count -> scan -> scatter. Appends to whatever the
// tables already hold (seeded from their current sizes), so it composes across windows. `executor` is
// bulk_for_each (CPU pool / future GPU stream) or serial_for_each; the scatter is identical either way.
template <class Graph, class Executor>
void ipv6_children_bulk(const std::vector<dag_packet>& pkts, ipv6_child_tables& kids, int root,
                        Executor&& executor) {
    const std::size_t np = pkts.size();

    // 1) count pass + 2) exclusive prefix-sum, seeded from current table sizes (cross-window append).
    std::vector<ipv6_child_counts> base(np);
    ipv6_child_counts run{static_cast<std::uint32_t>(kids.srh_segment.size()),
                          static_cast<std::uint32_t>(kids.opt.size())};
    for (std::size_t k = 0; k < np; ++k) {
        base[k] = run;
        run = run + count_packet_ipv6_children<Graph>(root, pkts[k].data, pkts[k].size);
    }

    // 3) size both child tables to their post-scan totals (no over-allocation, no push_back).
    kids.srh_segment.packet_id.resize(run.seg);
    kids.srh_segment.srh_order.resize(run.seg);
    kids.srh_segment.segment_index.resize(run.seg);
    kids.srh_segment.address.resize(run.seg);
    kids.opt.packet_id.resize(run.opt);
    kids.opt.container_type.resize(run.opt);
    kids.opt.opt_type.resize(run.opt);
    kids.opt.opt_len.resize(run.opt);

    // 4) bind the POD sink at the resized columns and scatter every packet into its prefix-summed slots.
    ipv6_child_sink sink{};
    sink.seg_pid = kids.srh_segment.packet_id.data();
    sink.seg_order = kids.srh_segment.srh_order.data();
    sink.seg_index = kids.srh_segment.segment_index.data();
    sink.seg_addr = reinterpret_cast<std::uint8_t*>(kids.srh_segment.address.data());  // 16 bytes/row, contiguous
    sink.opt_pid = kids.opt.packet_id.data();
    sink.opt_container = kids.opt.container_type.data();
    sink.opt_type = kids.opt.opt_type.data();
    sink.opt_len = kids.opt.opt_len.data();

    const dag_packet* pp = pkts.data();
    const ipv6_child_counts* bp = base.data();
    const std::size_t num_tasks = std::min<std::size_t>(np, 64);
    executor(num_tasks, np, [=](std::size_t k) {
        scatter_packet_ipv6_children<Graph>(pp[k].packet_id, root, pp[k].data, pp[k].size, bp[k], sink);
    });
}

}  // namespace nanotins
