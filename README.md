# ARMDisasm
Disassemble .so (NDK, JNI) files on Android. Capstone-based disassembler application on android

# Features
- Shows details of elf files.
- Disassembles the entire code sections.
- Has various export options of  the disassembly.
- Highlights branch instructions.
- Has Instant analysis mode.

# Usuage
1. Choose an elf file to analyze.
1. Go to details tab.
1. Press `Show details` button to see details.
1. Press `Save to file` button to save it.
1. Go to disassembly tab.
1. Press `disassemble` button.
1. Choose instant mode or persist mode.
1. To export the disassembly, press `Export` button and choose the option.

# Analysis mode
 - Instant mode
Fast and lightweight, but buggy.
 - Persist mode
A bit lags, but OK

# Export mode
 - Classic
Pretty!
 - Simple
Can be directly pasted as code!
 - Json
It can be loaded again to analyze again(though reloading is not implemented yet - Sorry:( )

# Permissions

Before using the app you need some steps:
**Granting permissions**

![image](images/Screenshot_20180926-090152.png)
![image](images/Screenshot_20180926-090201.png)

# ScreenShots
![image](images/Screenshot_20180926-090313.png?rw)
![image](images/Screenshot_20180926-090316.png)
![image](images/Screenshot_20180926-090327.png)
![image](images/Screenshot_20180926-090417.png)


# Build
I use [AIDE](https://play.google.com/store/apps/details?id=com.aide.ui) to build the project.

As AIDE doesn't seem to support gradle&JNI mixed project you need to downliad some library projects.

https://github.com/dandar3/android-support-v7-appcompat

And [modified storagechooser-2.](https://github.com/KYHSGeekCode/storage-chooser-2-android-buildable-libtary-project)

# Open Source
 - This app used [Capstone](https://github.com/aquynh/capstone), and [Colorpickerview](https://github.com/danielnilsson9/color-picker-view).