# nanotins — a layered C++20 packet-parsing stack, three header-only libraries that each vendor on their own:
#
#   soatins   the reusable "describe a struct once -> SoA + Arrow" reflection nucleus (nanoarrow + boost).
#   nanotins  pcap/pcapng + L2/L3/L4 parsing, the wire_spec/DAG core, and a scheduler-agnostic bulk path
#             (depends on soatins + stdexec).
#   gputins   the CUDA (nvexec) executors, header-only and guarded by NANOTINS_ENABLE_CUDA
#             (depends on nanotins; inert on a CPU-only build).
#
# This top-level project exists so a consumer can pull the whole stack with a single add_subdirectory():
#
#   add_subdirectory(extern/nanotins)             # creates soatins::core, nanotins, gputins
#   target_link_libraries(my_app PRIVATE nanotins)
#
# Each subdirectory is also independently configurable on its own (PROJECT_IS_TOP_LEVEL), and pulls its own
# external deps via FetchContent when they are not already targets in the parent build.

cmake_minimum_required(VERSION 3.20)
project(nanotins_suite CXX)

# Build every library's unit tests. Defaults ON for a standalone suite build, OFF when this is embedded as a
# subdirectory of a larger project (which sets SOATINS_BUILD_TESTS / NANOTINS_BUILD_TESTS itself).
option(NANOTINS_SUITE_BUILD_TESTS "Build soatins + nanotins unit tests" ${PROJECT_IS_TOP_LEVEL})
if(NANOTINS_SUITE_BUILD_TESTS)
    enable_testing()
    set(SOATINS_BUILD_TESTS ON CACHE BOOL "" FORCE)
    set(NANOTINS_BUILD_TESTS ON CACHE BOOL "" FORCE)
endif()

# Dependency order: soatins -> nanotins -> gputins. Each guards against re-adding a layer that already
# exists as a target, so the order here is the single source of truth.
add_subdirectory(soatins)
add_subdirectory(nanotins)
add_subdirectory(gputins)
