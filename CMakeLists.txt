cmake_minimum_required(VERSION 2.6)

project(RoHC)

include_directories(include)

SET(SOURCES
	src/rohc.cpp
	src/compressor.cpp
	src/decomp.cpp
	src/network.cpp
	src/cprofile.cpp
	src/dprofile.cpp
	src/cudp_profile.cpp
	src/dudp_profile.cpp
	src/crtp_profile.cpp
	src/drtp_profile.cpp
	src/cuncomp_profile.cpp
	src/duncomp_profile.cpp
    src/ctcp_profile.cpp
    src/dtcp_profile.cpp
	src/lsb.cpp
	)

file(GLOB_RECURSE INCS "*.h")

add_library(rohc STATIC ${SOURCES} ${INCS})

option( BUILD_TESTER "Build tester program that can load pcap files" OFF )

if (BUILD_TESTER)
    add_subdirectory(pcap_tester)
endif()


