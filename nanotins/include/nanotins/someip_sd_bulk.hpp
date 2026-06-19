// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// Bulk decode of the SOME/IP-SD child tables (entries + options), using the same
// count -> exclusive prefix-sum -> scatter pattern as dag_bulk.hpp / ipv6_children_bulk.hpp, over the SAME
// NANOTINS_HD traversal (for_each_sd_child) the serial path uses — so the bulk output is byte-identical to
// the serial output (serial == bulk == future gpu). The scatter sink is a POD of raw pointers, so a CUDA
// bulk kernel can capture it unchanged; only the host orchestration (sizing the std::vectors) lives here.

#include "nanotins/bulk.hpp"
#include "nanotins/dag_bulk.hpp"  // dag_packet
#include "nanotins/someip_sd.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nanotins {

// Bulk-decode packets' SOME/IP-SD child records into `kids` via count -> scan -> scatter. Appends to whatever
// the tables already hold (seeded from their current sizes), so it composes across windows. `executor` is
// bulk_for_each (CPU pool / future GPU stream) or serial_for_each; the scatter is identical either way.
template <class Graph, class Executor>
void someip_sd_bulk(const std::vector<dag_packet>& pkts, someip_sd_child_tables& kids, int root,
                    Executor&& executor) {
    const std::size_t np = pkts.size();

    // 1) count pass + 2) exclusive prefix-sum, seeded from current table sizes (cross-window append).
    std::vector<someip_sd_child_counts> base(np);
    someip_sd_child_counts run{static_cast<std::uint32_t>(kids.entry.size()),
                               static_cast<std::uint32_t>(kids.option.size())};
    for (std::size_t k = 0; k < np; ++k) {
        base[k] = run;
        run = run + count_packet_someip_sd_children<Graph>(root, pkts[k].data, pkts[k].size);
    }

    // 3) size both child tables to their post-scan totals (no over-allocation, no push_back).
    auto& e = kids.entry;
    e.packet_id.resize(run.entry);
    e.entry_index.resize(run.entry);
    e.type.resize(run.entry);
    e.index_1st_opts.resize(run.entry);
    e.index_2nd_opts.resize(run.entry);
    e.num_opt_1.resize(run.entry);
    e.num_opt_2.resize(run.entry);
    e.service_id.resize(run.entry);
    e.instance_id.resize(run.entry);
    e.major_version.resize(run.entry);
    e.ttl.resize(run.entry);
    e.minor_version.resize(run.entry);
    auto& o = kids.option;
    o.packet_id.resize(run.option);
    o.option_index.resize(run.option);
    o.length.resize(run.option);
    o.type.resize(run.option);
    o.l4proto.resize(run.option);
    o.port.resize(run.option);
    o.address.resize(run.option);

    // 4) bind the POD sink at the resized columns and scatter every packet into its prefix-summed slots.
    someip_sd_child_sink sink{};
    sink.entry_pid = e.packet_id.data();
    sink.entry_index = e.entry_index.data();
    sink.entry_type = e.type.data();
    sink.entry_index_1st = e.index_1st_opts.data();
    sink.entry_index_2nd = e.index_2nd_opts.data();
    sink.entry_num_opt_1 = e.num_opt_1.data();
    sink.entry_num_opt_2 = e.num_opt_2.data();
    sink.entry_service_id = e.service_id.data();
    sink.entry_instance_id = e.instance_id.data();
    sink.entry_major_version = e.major_version.data();
    sink.entry_ttl = e.ttl.data();
    sink.entry_minor_version = e.minor_version.data();
    sink.opt_pid = o.packet_id.data();
    sink.opt_index = o.option_index.data();
    sink.opt_length = o.length.data();
    sink.opt_type = o.type.data();
    sink.opt_l4proto = o.l4proto.data();
    sink.opt_port = o.port.data();
    sink.opt_addr = reinterpret_cast<std::uint8_t*>(o.address.data());  // 16 bytes/row, contiguous

    const dag_packet* pp = pkts.data();
    const someip_sd_child_counts* bp = base.data();
    const std::size_t num_tasks = std::min<std::size_t>(np, 64);
    executor(num_tasks, np, [=](std::size_t k) {
        scatter_packet_someip_sd_children<Graph>(pp[k].packet_id, root, pp[k].data, pp[k].size, bp[k], sink);
    });
}

}  // namespace nanotins
