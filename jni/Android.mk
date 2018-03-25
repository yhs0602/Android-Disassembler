# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.cpprg/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS+=-D __STDC_LIMIT_MACROS -D __STDC_FORMAT_MACROS -L libcapstone -L capstone

LOCAL_CPP_EXTENSION := .cpp .cc
LOCAL_MODULE    := hello-jni
LOCAL_SRC_FILES += hello-jni.cpp

ifeq ($(TARGET_ARCH_ABI),x86)
    LOCAL_CFLAGS += -ffast-math -mtune=atom -mssse3 -mfpmath=sse
endif
# libadd.so 는 LibTest1/libs/armeabi 에
# libsubtract.so  는 LibTest2/libs/armeabi 에 있다고 가정합니다.

LOCAL_LDLIBS := -L$(call host-path, $(LOCAL_PATH)/libs/armeabi)\
				-L$(call host-path, $(LOCAL_PATH)/libs/x86)\
				-lz -lm
				
#LOCAL_STATIC_LIBRARIES:=capstone capstone.a libcapstone 
#LOCAL_WHOLE_STATIC_LIBRARIES+=capstone.a
ifeq ($(TARGET_ARCH_ABI),x86)
LOCAL_STATIC_LIBRARIES := capstone_static_x86
else
LOCAL_STATIC_LIBRARIES := capstone_static_arm 
endif
#LOCAL_LDLIBS           := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := capstone_static_arm
LOCAL_SRC_FILES := /storage/emulated/0/AppProjects/ARMDisasm/libs/armeabi-v7a/libcapstone.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := capstone_static_x86
LOCAL_SRC_FILES := /storage/emulated/0/AppProjects/ARMDisasm/libs/x86/libcapstone.a
include $(PREBUILT_STATIC_LIBRARY)
