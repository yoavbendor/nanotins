# dpar — Dynamic Parser Application Rules example (pcap/pcapng + a rules file -> per-rule NDJSON tables).
# Depends only on the nanotins umbrella target. The conversion core (dpar_example.hpp) is header-only so it
# is also unit-tested in-process. This example is the worked "lib user brings their own parser Kind and
# drives it from a CLI rule" demo (OddTlvKind, composed into the palette alongside the built-ins).

add_executable(dpar dpar_main.cpp)
target_include_directories(dpar PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(dpar PRIVATE nanotins)

if(NANOTINS_BUILD_TESTS)
    # Smoke test: builds a synthetic SOME/IP-TLV-over-UDP pcapng and checks the rule-driven NDJSON
    # in-process. Uses the shared pcap_fixtures.hpp from the nanotins unit tests.
    add_executable(dpar_example_smoke test_dpar_example.cpp)
    target_include_directories(dpar_example_smoke PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../../nanotins/tests")
    target_link_libraries(dpar_example_smoke PRIVATE nanotins)
    add_test(NAME dpar_example_smoke COMMAND $<TARGET_FILE:dpar_example_smoke>)
    set_tests_properties(dpar_example_smoke PROPERTIES LABELS "smoke")
endif()
