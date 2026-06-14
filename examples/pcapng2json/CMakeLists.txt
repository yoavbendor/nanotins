# pcapng2json — a parser-only nanotins example (pcap/pcapng -> NDJSON, no Lance). Depends only on the
# nanotins umbrella target. Built as part of a standalone suite build (NANOTINS_BUILD_EXAMPLES, default ON
# at top level); the conversion core is header-only so it is also unit-tested in-process.

add_executable(pcapng2json pcapng2json.cpp)
target_include_directories(pcapng2json PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(pcapng2json PRIVATE nanotins)

if(NANOTINS_BUILD_TESTS)
    # Smoke test: builds a synthetic Ethernet/IPv4/UDP capture and checks the NDJSON in-process. Uses the
    # shared pcap_fixtures.hpp from the nanotins unit tests.
    add_executable(pcapng2json_smoke test_pcapng2json.cpp)
    target_include_directories(pcapng2json_smoke PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../../nanotins/tests")
    target_link_libraries(pcapng2json_smoke PRIVATE nanotins)
    add_test(NAME pcapng2json_smoke COMMAND $<TARGET_FILE:pcapng2json_smoke>)
    set_tests_properties(pcapng2json_smoke PROPERTIES LABELS "smoke")
endif()
