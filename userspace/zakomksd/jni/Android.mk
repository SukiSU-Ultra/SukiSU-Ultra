LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := zakomksd
LOCAL_SRC_FILES := zakomksd.c
include $(BUILD_EXECUTABLE)
