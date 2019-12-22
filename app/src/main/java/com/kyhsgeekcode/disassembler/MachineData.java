package com.kyhsgeekcode.disassembler;

import android.util.Log;

import nl.lxtreme.binutils.elf.MachineType;

public class MachineData {
    private static final String TAG = "ADA MachineData";


    public static final int CS_ARCH_ARM = 0;
    public static final int CS_ARCH_ARM64 = 1;
    public static final int CS_ARCH_MIPS = 2;
    public static final int CS_ARCH_X86 = 3;
    public static final int CS_ARCH_PPC = 4;
    public static final int CS_ARCH_SPARC = 5;
    public static final int CS_ARCH_SYSZ = 6;
    public static final int CS_ARCH_XCORE = 7;
    public static final int CS_ARCH_MAX = 8;
    public static final int CS_ARCH_ALL = 0xFFFF; // query id for cs_support()
    public static final int CS_MODE_LITTLE_ENDIAN = 0;    // little-endian mode (default mode)
    public static final int CS_MODE_ARM = 0;    // 32-bit ARM
    public static final int CS_MODE_16 = 1 << 1;    // 16-bit mode (X86)
    public static final int CS_MODE_32 = 1 << 2;    // 32-bit mode (X86)
    public static final int CS_MODE_64 = 1 << 3;    // 64-bit mode (X86; PPC)
    public static final int CS_MODE_THUMB = 1 << 4;    // ARM's Thumb mode; including Thumb-2
    public static final int CS_MODE_MCLASS = 1 << 5;    // ARM's Cortex-M series
    public static final int CS_MODE_V8 = 1 << 6;    // ARMv8 A32 encodings for ARM
    public static final int CS_MODE_MICRO = 1 << 4; // MicroMips mode (MIPS)
    public static final int CS_MODE_MIPS3 = 1 << 5; // Mips III ISA
    public static final int CS_MODE_MIPS32R6 = 1 << 6; // Mips32r6 ISA
    public static final int CS_MODE_MIPSGP64 = 1 << 7; // General Purpose Registers are 64-bit wide (MIPS)
    public static final int CS_MODE_V9 = 1 << 4; // SparcV9 mode (Sparc)
    public static final int CS_MODE_BIG_ENDIAN = 1 << 31;    // big-endian mode
    public static final int CS_MODE_MIPS32 = CS_MODE_32;    // Mips32 ISA (Mips)
    public static final int CS_MODE_MIPS64 = CS_MODE_64;    // Mips64 ISA (Mips)

    public static int[] getArchitecture(MachineType type) {

        switch (type) {
            case NONE://(0, "No machine"),
                return new int[]{CS_ARCH_ALL};
            case M32://(1, "AT&T WE 32100"),
            case SPARC://(2, "SUN SPARC"),
                return new int[]{CS_ARCH_SPARC};
            case i386: //(3, "Intel 80386"),
                return new int[]{CS_ARCH_X86, CS_MODE_32};
            case m68K: //(4, "Motorola m68k family"),
            case m88K: //(5, "Motorola m88k family"),
            case i860: //(7, "Intel 80860"),
                return new int[]{CS_ARCH_X86, CS_MODE_32};
            case MIPS: //(8, "MIPS R3000 big-endian"),
                return new int[]{CS_ARCH_MIPS};
            case S370: //(9, "IBM System/370"),
            case MIPS_RS3_LE: //(10, "MIPS R3000 little-endian"),
                return new int[]{CS_ARCH_MIPS};
            case PARISC: //(15, "HPPA"),
            case VPP500: //(17, "Fujitsu VPP500"),
            case SPARC32PLUS: //(18, "Sun's \"v8plus\""),
            case i960: //(19, "Intel 80960"),
                return new int[]{CS_ARCH_X86, CS_MODE_32};
            case PPC: //(20, "PowerPC"),
                return new int[]{CS_ARCH_PPC};
            case PPC64: //(21, "PowerPC 64-bit"),
                return new int[]{CS_ARCH_PPC};
            case S390: //(22, "IBM S390"),

            case V800: //(36, "NEC V800 series"),
            case FR20: //(37, "Fujitsu FR20"),
            case RH32: //(38, "TRW RH-32"),
            case RCE: //(39, "Motorola RCE"),
            case ARM: //(40, "ARM"),
                return new int[]{CS_ARCH_ARM};
            case FAKE_ALPHA: //(41, "Digital Alpha"),
            case SH: //(42, "Hitachi SH"),
            case SPARCV9: //(43, "SPARC v9 64-bit"),
                return new int[]{CS_ARCH_SPARC};
            case TRICORE: //(44, "Siemens Tricore"),
            case ARC: //(45, "Argonaut RISC Core"),
            case H8_300: //(46, "Hitachi H8/300"),
            case H8_300H: //(47, "Hitachi H8/300H"),
            case H8S: //(48, "Hitachi H8S"),
            case H8_500: //(49, "Hitachi H8/500"),
            case IA_64: //(50, "Intel Merced"),
                return new int[]{CS_ARCH_X86};
            case MIPS_X: //(51, "Stanford MIPS-X"),
                return new int[]{CS_ARCH_MIPS};
            case COLDFIRE: //(52, "Motorola Coldfire"),
            case m68HC12: //(53, "Motorola M68HC12"),
            case MMA: //(54, "Fujitsu MMA Multimedia Accelerator"),
            case PCP: //(55, "Siemens PCP"),
            case NCPU: //(56, "Sony nCPU embeeded RISC"),
            case NDR1: //(57, "Denso NDR1 microprocessor"),
            case STARCORE: //(58, "Motorola Start*Core processor"),
            case ME16: //(59, "Toyota ME16 processor"),
            case ST100: //(60, "STMicroelectronic ST100 processor"),
            case TINYJ: //(61, "Advanced Logic Corp. Tinyj emb.fam"),
            case x86_64: //(62, "x86-64"),
                return new int[]{CS_ARCH_X86};
            case PDSP: //(63, "Sony DSP Processor"),

            case FX66: //(66, "Siemens FX66 microcontroller"),
            case ST9PLUS: //(67, "STMicroelectronics ST9+ 8/16 mc"),
            case ST7: //(68, "STmicroelectronics ST7 8 bit mc"),
            case m68HC16: //(69, "Motorola MC68HC16 microcontroller"),
            case m68HC11: //(70, "Motorola MC68HC11 microcontroller"),
            case m68HC08: //(71, "Motorola MC68HC08 microcontroller"),
            case m68HC05: //(72, "Motorola MC68HC05 microcontroller"),
            case SVX: //(73, "Silicon Graphics SVx"),
            case ST19: //(74, "STMicroelectronics ST19 8 bit mc"),
            case VAX: //(75, "Digital VAX"),
            case CRIS: //(76, "Axis Communications 32-bit embedded processor"),
            case JAVELIN: //(77, "Infineon Technologies 32-bit embedded processor"),
            case FIREPATH: //(78, "Element 14 64-bit DSP Processor"),
            case ZSP: //(79, "LSI Logic 16-bit DSP Processor"),
            case MMIX: //(80, "Donald Knuth's educational 64-bit processor"),
            case HUANY: //(81, "Harvard University machine-independent object files"),
            case PRISM: //(82, "SiTera Prism"),
            case AVR: //(83, "Atmel AVR 8-bit microcontroller"),
            case FR30: //(84, "Fujitsu FR30"),
            case D10V: //(85, "Mitsubishi D10V"),
            case D30V: //(86, "Mitsubishi D30V"),
            case V850: //(87, "NEC v850"),
            case M32R: //(88, "Mitsubishi M32R"),
            case MN10300: //(89, "Matsushita MN10300"),
            case MN10200: //(90, "Matsushita MN10200"),
            case PJ: //(91, "picoJava"),
            case OPENRISC: //(92, "OpenRISC 32-bit embedded processor"),
            case ARC_A5: //(93, "ARC Cores Tangent-A5"),
            case XTENSA: //(94, "Tensilica Xtensa Architecture"),
            case AARCH64: //(183, "ARM AARCH64"),
                return new int[]{CS_ARCH_ARM64};
            case TILEPRO: //(188, "Tilera TILEPro"),
            case MICROBLAZE: //(189, "Xilinx MicroBlaze"),
            case TILEGX: //(191, "Tilera TILE-Gx")};

        }
        Log.e(TAG, "Unsupported machine!!" + type.name());
        return new int[]{CS_ARCH_ALL};
    }
}
