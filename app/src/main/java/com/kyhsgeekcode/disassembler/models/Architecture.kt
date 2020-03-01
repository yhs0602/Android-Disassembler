package com.kyhsgeekcode.disassembler.models

import android.util.Log
import nl.lxtreme.binutils.elf.MachineType

object Architecture {
    const val CS_ARCH_ARM = 0
    const val CS_ARCH_ARM64 = 1
    const val CS_ARCH_MIPS = 2
    const val CS_ARCH_X86 = 3
    const val CS_ARCH_PPC = 4
    const val CS_ARCH_SPARC = 5
    const val CS_ARCH_SYSZ = 6
    const val CS_ARCH_XCORE = 7
    const val CS_ARCH_MAX = 8
    const val CS_ARCH_ALL = 0xFFFF // query id for cs_support()
    const val CS_MODE_LITTLE_ENDIAN = 0 // little-endian mode (default mode)
    const val CS_MODE_ARM = 0 // 32-bit ARM
    const val CS_MODE_16 = 1 shl 1 // 16-bit mode (X86)
    const val CS_MODE_32 = 1 shl 2 // 32-bit mode (X86)
    const val CS_MODE_64 = 1 shl 3 // 64-bit mode (X86; PPC)
    const val CS_MODE_THUMB = 1 shl 4 // ARM's Thumb mode; including Thumb-2
    const val CS_MODE_MCLASS = 1 shl 5 // ARM's Cortex-M series
    const val CS_MODE_V8 = 1 shl 6 // ARMv8 A32 encodings for ARM
    const val CS_MODE_MICRO = 1 shl 4 // MicroMips mode (MIPS)
    const val CS_MODE_MIPS3 = 1 shl 5 // Mips III ISA
    const val CS_MODE_MIPS32R6 = 1 shl 6 // Mips32r6 ISA
    const val CS_MODE_MIPSGP64 = 1 shl 7 // General Purpose Registers are 64-bit wide (MIPS)
    const val CS_MODE_V9 = 1 shl 4 // SparcV9 mode (Sparc)
    const val CS_MODE_BIG_ENDIAN = 1 shl 31 // big-endian mode
    const val CS_MODE_MIPS32 = CS_MODE_32 // Mips32 ISA (Mips)
    const val CS_MODE_MIPS64 = CS_MODE_64 // Mips64 ISA (Mips)
    fun getArchitecture(type: MachineType): IntArray {
        when (type) {
            MachineType.NONE -> return intArrayOf(CS_ARCH_ALL)
            MachineType.M32, MachineType.SPARC -> return intArrayOf(CS_ARCH_SPARC)
            MachineType.i386 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
            MachineType.m68K, MachineType.m88K, MachineType.i860 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
            MachineType.MIPS -> return intArrayOf(CS_ARCH_MIPS)
            MachineType.S370, MachineType.MIPS_RS3_LE -> return intArrayOf(CS_ARCH_MIPS)
            MachineType.PARISC, MachineType.VPP500, MachineType.SPARC32PLUS, MachineType.i960 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
            MachineType.PPC -> return intArrayOf(CS_ARCH_PPC)
            MachineType.PPC64 -> return intArrayOf(CS_ARCH_PPC)
            MachineType.S390, MachineType.V800, MachineType.FR20, MachineType.RH32, MachineType.RCE, MachineType.ARM -> return intArrayOf(CS_ARCH_ARM)
            MachineType.FAKE_ALPHA, MachineType.SH, MachineType.SPARCV9 -> return intArrayOf(CS_ARCH_SPARC)
            MachineType.TRICORE, MachineType.ARC, MachineType.H8_300, MachineType.H8_300H, MachineType.H8S, MachineType.H8_500, MachineType.IA_64 -> return intArrayOf(CS_ARCH_X86)
            MachineType.MIPS_X -> return intArrayOf(CS_ARCH_MIPS)
            MachineType.COLDFIRE, MachineType.m68HC12, MachineType.MMA, MachineType.PCP, MachineType.NCPU, MachineType.NDR1, MachineType.STARCORE, MachineType.ME16, MachineType.ST100, MachineType.TINYJ, MachineType.x86_64 -> return intArrayOf(CS_ARCH_X86)
            MachineType.PDSP, MachineType.FX66, MachineType.ST9PLUS, MachineType.ST7, MachineType.m68HC16, MachineType.m68HC11, MachineType.m68HC08, MachineType.m68HC05, MachineType.SVX, MachineType.ST19, MachineType.VAX, MachineType.CRIS, MachineType.JAVELIN, MachineType.FIREPATH, MachineType.ZSP, MachineType.MMIX, MachineType.HUANY, MachineType.PRISM, MachineType.AVR, MachineType.FR30, MachineType.D10V, MachineType.D30V, MachineType.V850, MachineType.M32R, MachineType.MN10300, MachineType.MN10200, MachineType.PJ, MachineType.OPENRISC, MachineType.ARC_A5, MachineType.XTENSA, MachineType.AARCH64 -> return intArrayOf(CS_ARCH_ARM64)
            MachineType.TILEPRO, MachineType.MICROBLAZE, MachineType.TILEGX -> {
            }
        }
        Log.e("Architecture", "Unsupported machine!!" + type.name)
        return intArrayOf(CS_ARCH_ALL)
    }
}
