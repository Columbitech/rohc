cmake_minimum_required(VERSION 2.8)

project(RoHC)

include_directories(../../include)

SET(SOURCES
	rohc.cpp
	compressor.cpp
	decomp.cpp
	network.cpp
	cprofile.cpp
	dprofile.cpp
	cudp_profile.cpp
	dudp_profile.cpp
	crtp_profile.cpp
	drtp_profile.cpp
	cuncomp_profile.cpp
	duncomp_profile.cpp
        ctcp_profile.cpp
        dtcp_profile.cpp
	lsb.cpp
	)

file(GLOB_RECURSE INCS "*.h")

add_library(rohc STATIC ${SOURCES} ${INCS})
