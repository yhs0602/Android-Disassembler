# Structure of this project

# Activities
## 1. MainActivity
This is the main activity of this project. It manages the general UI.
## 2. SettingsActivity
This is the activity managing settings.

# Packages
## 1. The capstone package
It is the java binding of capstone. Currently not used exept for constants, for speed.
## 2. The com.kyhsgeekcode.rootpicker package
It is a package for a file picker that allows users to pick files that requires root to access.
## 3. The com.kyhsgeekcode.disassembler package
This is the main package.

# JNIs
The capstone's source code resides here.
**[hello-jni.cpp](https://github.com/KYHSGeekCode/Android-Disassembler/blob/master/app/src/main/cpp/hello-jni.cpp)** links the capstone library and the java part. Also the plthook's source code is here, though not used currently.
