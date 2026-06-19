# lldp — an instructive example of a user ADDING THEIR OWN PROTOCOL PARSER (LLDP, an L2/Ethernet
# protocol) and applying it with DPAR rules: pcap/pcapng + a rules file -> per-TLV NDJSON. Depends only
# on the nanotins umbrella target. The parser + Kind core (lldp.hpp) is header-only so it is also
# unit-tested in-process. See lldp.hpp for the heavily-commented walkthrough.

add_executable(lldp lldp_main.cpp)
target_include_directories(lldp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(lldp PRIVATE nanotins)

if(NANOTINS_BUILD_TESTS)
    # Smoke test: bounded TLV cursor + the end-to-end "rule applies LLDP over the L2 payload" path on a
    # synthetic eth/0x88CC pcapng. Uses the shared pcap_fixtures.hpp from the nanotins unit tests.
    add_executable(lldp_smoke test_lldp.cpp)
    target_include_directories(lldp_smoke PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../../nanotins/tests")
    target_link_libraries(lldp_smoke PRIVATE nanotins)
    add_test(NAME lldp_smoke COMMAND $<TARGET_FILE:lldp_smoke>)
    set_tests_properties(lldp_smoke PROPERTIES LABELS "smoke")
endif()
