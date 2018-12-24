# Version 1.4.1.1 [release](https://github.com/KYHSGeekCode/Android-Disassembler/releases)!
### Sorry, saved raw disasms are now incompatible with this version!

# Android-Disassembler
Disassemble **ANY** files including android shared libraries (aka .so files) (NDK, JNI), windows PE files(EXE, DLLs, SYSs, etc..), linux executables, object files, ANY files you want like pictures, audios, etc(for fun) entirely on Android. Capstone-based disassembler application on android.

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

# What's new
- Colorize PUSH/POP instructions.
- Colorize ARM arch instructions better.
- Added **Follow Jump** menu for jump instructions.(*With BackStack*)
- Can override auto parse setup

# New [theme](https://github.com/KYHSGeekCode/Android-Disassembler/tree/master/themes)!
 - KYHSGeekCode theme!
 ![image](images/Screenshot_20181221-215203.png)![image](images/Screenshot_20181221-215647.png)![image](images/Screenshot_20181222-173614.png)

# Usuage
1. Choose a file to analyze.
![image](images/Screenshot_20181222-213649.png)
1. Go to details tab.
1. Press `Show details` button to see details.
![image](images/Screenshot_20181022-192953.png)
1. Press `Save to file` button to save it.
1. Go to Symbols tab.
1. You can see symbols found in the elf file, their demangled names(if they exist), addresses, and their properties.
![image](images/Screenshot_20181022-193032.png)
![image](images/Screenshot_20181022-193042.png)
1. Go to disassembly tab.
![image](images/Screenshot_20181217-112755.png)
1. To export the disassembly, press `Export` button and choose the option.
![image](images/Screenshot_20181022-193127.png)

# Export mode
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
Here are some common issues and some solutons for them.
 - The app crashes!

   Sorry for inconvenience, please send an error report as an issue. **If you can't wait for the next stable version, please check / grant the read/write permission to the app.**
   
 - NotThisFormatException

   Is it a well known executable file? (ELF:`.so, .o, .lib, .a, etc..`, PE:`.exe, .dll, .sys, ...`) Then please report me with the file you tried to disassemble.
   If not, you need to press `OK` and **setup manually**.

# Theme management
You can download the theme.zip here.
 1. Unzip it to `/storage/emulated/0/themes/` or `/sdcard/themes`.
 1. Done. You can now use this in settings menu(in app)


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


# TODO
 - add jump feature on clicking disassemblies.
 - Show prototypes of NDK/C standard APIs in the symbols tab.
 - More sophisticated colorizing.
 - Generate more useful comments
 - Provide assembly tutorials.
 - Parse PLT/IAT, EAT

# Thanks
https://reverseengineering.stackexchange.com/a/20124/23870

# XRefs
https://reverseengineering.stackexchange.com/a/18203/23870