# Sets the minimum version of CMake required to build your native library.
# This ensures that a certain set of CMake features is available to
# your build.

cmake_minimum_required(VERSION 3.4.1)

# Specifies a library name, specifies whether the library is STATIC or
# SHARED, and provides relative paths to the source code. You can
# define multiple libraries by adding multiple add.library() commands,
# and CMake builds them for you. When you build your app, Gradle
# automatically packages shared libraries with your APK.

add_library( # Specifies the name of the library.
        native-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        src/main/cpp/native-lib.cpp
        src/main/cpp/plthook/plthook_elf.c
        #src/main/cpp/plthook/plthook_osx.c
        #src/main/cpp/plthook/plthook_win32.c

        )

find_library( # Defines the name of the path variable that stores the
        # location of the NDK library.
        log-lib

        # Specifies the name of the NDK library that
        # CMake needs to locate.
        log)

# Links your native library against one or more other native libraries.
#target_link_libraries( # Specifies the target library.
#                       native-lib
#
#                      # Links the log library to the target library.
#                       ${log-lib} )

#add_library( capstone
#        SHARED
#        IMPORTED )

#set_target_properties( # Specifies the target library.
#        capstone
#
#        # Specifies the parameter you want to define.
#        PROPERTIES IMPORTED_LOCATION#
#
#        # Provides the path to the library you want to import.
#        C:/Users/82102/AndroidStudioProjects/Android-Disassembler/capstone/${ANDROID_ABI}/libcapstone. )

target_link_libraries(native-lib C:/Users/82102/AndroidStudioProjects/Android-Disassembler/capstone/${ANDROID_ABI}/libcapstone.a ${log-lib}) #app-glue


include_directories(capstone/include/)