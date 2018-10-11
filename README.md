# Version 1.0.0 [release](https://github.com/KYHSGeekCode/Android-Disassembler/releases)!

# Android-Disassembler
Disassemble .so (NDK, JNI) files on Android. Capstone-based disassembler application on android

# Features
- Shows details of elf files.
- Disassembles the entire code sections.
- Has various export options of the disassembly. (Compilable txt file, analytic text files, json, and reloadable database)
- Highlights branch instructions.
- Has Instant analysis mode.
- Supports projects.
- Supports launching from file browsers.

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
![image](images/Screenshot_20181007-193746.png)
![image](images/Screenshot_20181007-193752.png)
![image](images/Screenshot_20181007-193758.png)


# Build
Use Android studio.

# Open Source
 This app used
 - [Capstone](https://github.com/aquynh/capstone) 
 - [Storage-Chooser](https://github.com/codekidX/storage-chooser)
 - [Colorpickerview](https://github.com/danielnilsson9/color-picker-view)
 - [Java-binutils](https://github.com/jawi/java-binutils)
 - [PECOFF4J](https://github.com/kichik/pecoff4j).

# What's new
 - Changed to Android Studio structure.
 - Supports various disasm export options.
 - Supports open from file browsers.
 - Supports x86 shared libraries.
 - Doesn't require your email accounts when sending error reports
 - Easier bug report

# TODO
 - Optimize saving disassemblies
 - Support x86 files. (Done..?)
 - fix bugs
 - add menus on clicking disassemblies.
 - add Syntax highlighting in disassemblies.
 - Add more project export options(zip, etc..)
 - Show function names as entry point. (https://ja.stackoverflow.com/questions/49106/elf-ファイルのdynamicセクションの情報を読み込み-外部にexportされている関数の名前と住所を見せたいと思います) I am not good at Japanese but I had to post here for some reasons.
 - Support exe files.
 - Organize spaghetti codes.
 - Add theme preferences.