LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

foo

LOCAL_MODULE    := rohc
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/include/
LOCAL_SRC_FILES := \
        src/compressor.cpp \
	src/cprofile.cpp \
	src/crtp_profile.cpp \
	src/ctcp_profile.cpp \
	src/cudp_profile.cpp \
	src/cuncomp_profile.cpp \
	src/decomp.cpp \
	src/dprofile.cpp \
	src/drtp_profile.cpp \
	src/dtcp_profile.cpp \
	src/dudp_profile.cpp \
	src/duncomp_profile.cpp \
	src/lsb.cpp \
	src/network.cpp \
	src/rohc.cpp 
        
include $(BUILD_STATIC_LIBRARY)

