
SET(SOURCES
    pcap_tester.cpp
    rohc_support.cpp
	)

file(GLOB_RECURSE INCS "*.h")

add_executable(pcap_tester ${SOURCES} ${INCS})
target_link_libraries(pcap_tester rohc pcap)
