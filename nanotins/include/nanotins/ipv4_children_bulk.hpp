// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// Bulk decode of the IPv4 option child table, using the same count -> exclusive prefix-sum -> scatter
// pattern as dag_bulk.hpp / ipv6_children_bulk.hpp, over the SAME NANOTINS_HD traversal
// (for_each_ipv4_opt) the serial path uses — so the bulk output is byte-identical to the serial output
// (serial == bulk == future gpu). The scatter sink is a POD of raw pointers, so a CUDA bulk kernel can
// capture it unchanged; only the host orchestration (sizing the std::vectors) lives here.

#include "nanotins/bulk.hpp"
#include "nanotins/dag_bulk.hpp"  // dag_packet
#include "nanotins/ipv4_children.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nanotins {

// Bulk-decode packets' IPv4 option records into `kids` via count -> scan -> scatter. Appends to whatever
// the table already holds (seeded from its current size), so it composes across windows. `executor` is
// bulk_for_each (CPU pool / future GPU stream) or serial_for_each; the scatter is identical either way.
template <class Graph, class Executor>
void ipv4_children_bulk(const std::vector<dag_packet>& pkts, ipv4_child_tables& kids, int root,
                        Executor&& executor) {
    const std::size_t np = pkts.size();

    // 1) count pass + 2) exclusive prefix-sum, seeded from the current table size (cross-window append).
    std::vector<ipv4_child_counts> base(np);
    ipv4_child_counts run{static_cast<std::uint32_t>(kids.opt.size())};
    for (std::size_t k = 0; k < np; ++k) {
        base[k] = run;
        run = run + count_packet_ipv4_children<Graph>(root, pkts[k].data, pkts[k].size);
    }

    // 3) size the child table to its post-scan total (no over-allocation, no push_back).
    kids.opt.packet_id.resize(run.opt);
    kids.opt.opt_type.resize(run.opt);
    kids.opt.opt_len.resize(run.opt);

    // 4) bind the POD sink at the resized columns and scatter every packet into its prefix-summed slots.
    ipv4_child_sink sink{};
    sink.opt_pid = kids.opt.packet_id.data();
    sink.opt_type = kids.opt.opt_type.data();
    sink.opt_len = kids.opt.opt_len.data();

    const dag_packet* pp = pkts.data();
    const ipv4_child_counts* bp = base.data();
    const std::size_t num_tasks = std::min<std::size_t>(np, 64);
    executor(num_tasks, np, [=](std::size_t k) {
        scatter_packet_ipv4_children<Graph>(pp[k].packet_id, root, pp[k].data, pp[k].size, bp[k], sink);
    });
}

}  // namespace nanotins
