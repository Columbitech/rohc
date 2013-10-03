LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := rohc
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../../include/
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../include/
LOCAL_SRC_FILES := \
        compressor.cpp \
	cprofile.cpp \
	crtp_profile.cpp \
	ctcp_profile.cpp \
	cudp_profile.cpp \
	cuncomp_profile.cpp \
	decomp.cpp \
	dprofile.cpp \
	drtp_profile.cpp \
	dtcp_profile.cpp \
	dudp_profile.cpp \
	duncomp_profile.cpp \
	lsb.cpp \
	network.cpp \
	rohc.cpp 
        
include $(BUILD_STATIC_LIBRARY)

