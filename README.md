# Android-Disassembler

[![ci][1]][2]
[![CodeFactor](https://www.codefactor.io/repository/github/kyhsgeekcode/android-disassembler/badge/master)](https://www.codefactor.io/repository/github/kyhsgeekcode/android-disassembler/overview/master)
[![Play Store Info](https://img.shields.io/badge/Play_Store-v2.0.3-36B0C1.svg?style=flat-square)](https://play.google.com/store/apps/details?id=com.kyhsgeekcode.disassembler)
[![HitCount](http://hits.dwyl.com/KYHSGeekCode/Android-Disassembler.svg)](http://hits.dwyl.com/KYHSGeekCode/Android-Disassembler)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=round)](https://github.com/KYHSGeekCode/Android-Disassembler/issues)
[![GitHub stars](https://img.shields.io/github/stars/KYHSGeekCode/Android-Disassembler.svg?style=social&label=Star&maxAge=2592000)](https://github.com/KYHSGeekCode/Android-Disassembler/stargazers/)

Analyze malicious app on your phone

Android Disassembler is an application that is able to analyze several types of files such as APK files, dex files, shared libraries (aka .so files) (NDK, JNI), windows PE files(EXE, DLLs, SYSs, etc..), linux executables, object files and much more. These app features are based on [capstone library](https://github.com/aquynh/capstone), [elf](https://github.com/serge1/ELFIO) [parser](https://github.com/jawi/java-binutils), [PE parser](https://github.com/kichik/pecoff4j), [backsmali](https://github.com/JesusFreke/smali), and [facile reflector](https://github.com/TomSmartBishop/facile-api).

[<img src="https://play.google.com/intl/en_us/badges/images/apps/en-play-badge-border.png" width="200" alt="Get Android Disassembler on Google Play" />](https://play.google.com/store/apps/details?id=com.kyhsgeekcode.disassembler "Get Android Disassembler on Google Play")

# Version 2.1.5 [release](https://github.com/KYHSGeekCode/Android-Disassembler/releases)!

## What's new : Fix several minor bug (crash)
# Features
- Shows details of elf files.
- Shows symbol table(functions or objects' ,... names) of elf files.
- Disassembles the code sections.
- Has various export options of the disassembly. (Reloadable raw file, compilable txt file, analytic text files, json, and  reloadable database)
- Supports projects.
- Supports **directly launching from file browsers**.
- Supports many ABIs(arm,x86,x64,MIPS,PowerPC,...)
- Jump to address by symbols' names, or a hex address.
- Syntax colorizing.
- Support PE and other bin formats.
- Sort symbols if needed.
- Colorize PUSH/POP instructions.
- Colorize ARM arch instructions better.
- Added **Follow Jump** menu for jump instructions.(*With BackStack*)
- Can override auto parse setup
- You can copy an instruction to the clipboard.
- It now parses *IAT, EAT* of PE headers.
- You can now choose the columns to view.
- Supports analyzing system files(which are not accessible without root permission) for rooted phones.
- Friendlier message for non-parsable files.
- The storage chooser now retains the session, so that it remembers the last browsed folder.
- Added Hex View and utility calculator.
- Theme installation is automated.
- Choose which binary to analyze when the zip/apk has multiple binaries.
- Choose **APK** from installed
- Search for strings in the binary (*Unfortunately only for ascii characters*)
- Bytewise analysis (mean, hashes, entropy, g-test, chi-test, autocorrelation) to help determine if the file is encrypted
- Support .NET assemblies
- Support dex files
- Analyzing multiple files in a project is allowed.

# Usage explanation video

[![Watch the video](https://img.youtube.com/vi/WZk0JdgSnTs/maxresdefault.jpg)](https://youtu.be/WZk0JdgSnTs)

# Materials about assemblies
 - [ARM](https://www.google.co.kr/url?sa=t&source=web&rct=j&url=http://arantxa.ii.uam.es/~gdrivera/sed/docs/ARMBook.pdf&ved=2ahUKEwjagIuEzOTeAhXHvLwKHeWcCnYQFjAAegQIBBAB&usg=AOvVaw2WWago0qaeDy06z0pgVR3n)
 - [ARM BlackHat](https://www.google.com/url?q=https://www.blackhat.com/presentations/bh-europe-04/bh-eu-04-dehaas/bh-eu-04-dehaas.pdf&sa=U&ved=2ahUKEwjzg-OCg-3eAhUFT7wKHfXlABIQFjACegQIChAB&usg=AOvVaw0JFoqyycNHnqauD5yO6jIj)
 - [Intel](https://en.m.wikibooks.org/wiki/X86_Assembly)
 - [Wiki](https://github.com/KYHSGeekCode/Android-Disassembler/wiki)

# Error Handling

 - The app crashes!

   Sorry for inconvenience, please send an error report as an issue. **If you can't wait for the next stable version, please check / grant the read/write permission to the app.**

 - NotThisFormatException

   Is it a well known executable file? (ELF:`.so, .o, .lib, .a, etc..`, PE:`.exe, .dll, .sys, ...`) Then please report me with the file you tried to disassemble.
   If not, you need to press `OK` and **setup manually**.


### Feature requests are welcomed!

# Build & Pull request
 - Use Android studio.
 - Any improvements are welcomed!

# Open Source
 This app used
 - [Capstone](https://github.com/aquynh/capstone)
 - [Storage-Chooser](https://github.com/codekidX/storage-chooser)
 - [Colorpickerview](https://github.com/skydoves/ColorPickerView)
 - [Java-binutils](https://github.com/jawi/java-binutils)
 - [PECOFF4J](https://github.com/kichik/pecoff4j).
 - [Root File Chooser](https://github.com/KYHSGeekCode/RootFilePicker)
 - [PhotoView](https://github.com/chrisbanes/PhotoView)
 - [Multi-level-Listview](https://github.com/open-rnd/android-multi-level-listview)
 - [Facile-api](https://github.com/TomSmartBishop/facile-api)
 - [plthook](https://github.com/kubo/plthook/)
 - [ELFIO](https://github.com/serge1/ELFIO) - bibliography: [TimScriptov/Disassembler](https://github.com/TimScriptov/Disassembler/blob/master/app/src/main/jni/Disassembler.cpp)
 - [apache commons compress](https://commons.apache.org/proper/commons-compress/)
 - [apache commons io](https://commons.apache.org/proper/commons-io/)
 - [LouisCAD/Splitties](https://github.com/LouisCAD/Splitties)
 - [Material-components-android](https://github.com/material-components/material-components-android)
 - [Kotlix coroutines](https://github.com/Kotlin/kotlinx.coroutines)
 - [SnackProgressBar](https://github.com/tingyik90/snackprogressbar)
 - [Spek](https://github.com/spekframework/spek)
 - [Kotlinx serialization](https://github.com/Kotlin/kotlinx.serialization)
 - [AndroidX](https://android.googlesource.com/platform/frameworks/support/+/androidx-master-dev)
 - [smali](https://github.com/JesusFreke/smali)
# TODO
 - Show prototypes of NDK/C standard APIs in the symbols tab.
 - More sophisticated colorizing
 - Generate more useful comments
 - Provide assembly tutorials.
 - Add pseudo-virtual machine to debug.
 - Allow users to analyze active processes.
 - Add arrow beside the disassembly.
 - Row selection
 - Better support for thumb assemblies
 - Add compatibility for OllyDbg's `.udd/.bak` files
 - Add compatibility for IDA's produce files.
 - About to add other utilities.
 - Add android resource analyzer
 - Let user choose file from google drive
 - Let user choose samples from web by hashes

# Thanks
https://reverseengineering.stackexchange.com/a/20124/23870

# XRefs
https://reverseengineering.stackexchange.com/a/18203/23870

# Privacy Policy
I think I have to notice you that:

- When the crash report with types such as `FileCorruptedException` is sent, the file you are analyzing may be attached to the bug report email, and be uploaded to the repository in `github.com`.

[1]: https://github.com/KYHSGeekCode/Android-Disassembler/workflows/ci/badge.svg
[2]: https://github.com/KYHSGeekCode/Android-Disassembler/actions
=======
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
