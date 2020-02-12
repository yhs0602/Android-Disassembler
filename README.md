[![Play Store Info](https://img.shields.io/badge/Play_Store-v1.4.7.1-36B0C1.svg?style=flat-square)](https://play.google.com/store/apps/details?id=com.kyhsgeekcode.disassembler)![Android CI](https://github.com/KYHSGeekCode/Android-Disassembler/workflows/Android%20CI/badge.svg)

[<img src="https://play.google.com/intl/en_us/badges/images/apps/en-play-badge-border.png" width="200" alt="Get Android Disassembler on Google Play" />](https://play.google.com/store/apps/details?id=com.kyhsgeekcode.disassembler "Get Android Disassembler on Google Play")

# Android-Disassembler - Analyze your malicious app on your phone

Disassemble **ANY** files including android shared libraries (aka .so files) (NDK, JNI), windows PE files(EXE, DLLs, SYSs, etc..), linux executables, object files, ANY files you want like pictures, audios, etc(for fun) entirely on Android. Capstone-based disassembler application on android.

# Version 1.6.2 [pre-release](https://github.com/KYHSGeekCode/Android-Disassembler/releases)!

## What's new : Support Kitkat
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
- No need to press `Disassemble` button!
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

# [Themes Download](https://github.com/KYHSGeekCode/Android-Disassembler/tree/master/themes)
 Good themes usually help you recognize some important instructions easily.

# Usage(1)

1. Browse to a file to analyze.

   The app automatically digs into `.zip, .apk, .dex` and `.NET assembly` files!

   ![](images/browseto.png)

   ![](images/chooseinstalled.png)

   ![](images/internal_storage.png)

1. You can just click to see the disassembled `.smali` files.

   ![](images/dex_opened.png)

1. Just by opening a .NET file like a folder, you can browse the symbols and methods defined.

   ![](images/dotnet_il.png)
   
1. You can view the decompiled `.smali` or `.il` files by clicking the method name.
   
   ![](images/open_ask.png)
   
   ![](images/opened_il.png)
   
   ![](images/opened_smali.png) 
   
   ![](images/system.math.png)
   
   

# Usage(2)

1. Choose a file to analyze.
![image](images/Screenshot_20181222-213649.png)
 - To change chooser, go to settings and change.
1. Go to details tab.
1. Press `Show details` button to see details.
(ELF)
![image](images/Screenshot_20181022-192953.png)
(PE)
![image](images/Screenshot_20190101-133237.png)
1. Press `Save to file` button to save it.
1. Go to Symbols tab.
1. You can see symbols found in the elf file, their demangled names(if they exist), addresses, and their properties.
![image](images/Screenshot_20181022-193032.png)
![image](images/Screenshot_20181022-193042.png)
![image](images/Screenshot_20190101-133256.png)
1. Go to disassembly tab.
![image](images/Screenshot_20181217-112755.png)
 ![image](images/Screenshot_20181221-215203.png)![image](images/Screenshot_20181221-215647.png)![image](images/Screenshot_20181222-173614.png)
1. To export the disassembly, press `Export` button and choose the option.
![image](images/Screenshot_20181022-193127.png)

# Export mode (Currently may not work well)
 - Raw
Uses java's intrinsic serialization, and super fast.
 - Classic
Pretty!
 - Simple
Can be directly pasted as code!
 - Json
It can be loaded again to analyze again(though reloading is not implemented yet - Sorry.)
 - Database
Slow. Not recommended.

# Materials about assemblies
 - [ARM](https://www.google.co.kr/url?sa=t&source=web&rct=j&url=http://arantxa.ii.uam.es/~gdrivera/sed/docs/ARMBook.pdf&ved=2ahUKEwjagIuEzOTeAhXHvLwKHeWcCnYQFjAAegQIBBAB&usg=AOvVaw2WWago0qaeDy06z0pgVR3n)
 - [ARM BlackHat](https://www.google.com/url?q=https://www.blackhat.com/presentations/bh-europe-04/bh-eu-04-dehaas/bh-eu-04-dehaas.pdf&sa=U&ved=2ahUKEwjzg-OCg-3eAhUFT7wKHfXlABIQFjACegQIChAB&usg=AOvVaw0JFoqyycNHnqauD5yO6jIj)
 - [Intel](https://en.m.wikibooks.org/wiki/X86_Assembly)
 - [Wiki](https://github.com/KYHSGeekCode/Android-Disassembler/wiki)

# Error Handling

### Sorry, saved raw disasms are now incompatible with this version!

Here are some common issues and some solutons for them.
 - The app crashes!

   Sorry for inconvenience, please send an error report as an issue. **If you can't wait for the next stable version, please check / grant the read/write permission to the app.**
   
 - NotThisFormatException

   Is it a well known executable file? (ELF:`.so, .o, .lib, .a, etc..`, PE:`.exe, .dll, .sys, ...`) Then please report me with the file you tried to disassemble.
   If not, you need to press `OK` and **setup manually**.

# Theme management -> you need not!
You can download the theme.zip here.
 1. Unzip it to `/storage/emulated/0/themes/` or `/sdcard/themes`.
 1. Done. You can now use this in settings menu(in app)
 1. To rename/remove themes, just rename/remove the files.


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
 - [LouisCAD/Splitties](https://github.com/LouisCAD/Splitties)
# TODO
 - Show prototypes of NDK/C standard APIs in the symbols tab.
 - More sophisticated colorizing
 - Generate more useful comments
 - Provide assembly tutorials.
 - Fix symbols bug.
 - Add pseudo-virtual machine to debug.
 - Allow users to analyze active processes.
 - Add arrow beside the disassembly.
 - Row selection
 - Better support for thumb assemblies
 - Add compatibility for OllyDbg's `.udd/.bak` files
 - Add compatibility for IDA's produce files.
 - About to add other utilities.
 - Add android resource analyzer
 - Improve elf parser
 - Improve file(data source) chooser

# Help wanted!
 - Don't the symbols' names look odd?

# Thanks
https://reverseengineering.stackexchange.com/a/20124/23870

# XRefs
https://reverseengineering.stackexchange.com/a/18203/23870

# Privacy Policy
I think I have to notice you that:

- When the crash report with types such as `FileCorruptedException` is sent, the file you are analyzing may be attached to the bug report email, and be uploaded to the repository in `github.com`.
