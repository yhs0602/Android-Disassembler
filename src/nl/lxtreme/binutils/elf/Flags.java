/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Contains logic for interpreting the flags (e_flags) field in a ELF-header.
 */
public interface Flags {
    /* Motorola 68k specific definitions. */
    int EF_CPU32 = 0x00810000;

    /* SUN SPARC specific definitions. */
    int EF_SPARCV9_MM = 3;
    int EF_SPARCV9_TSO = 0;
    int EF_SPARCV9_PSO = 1;
    int EF_SPARCV9_RMO = 2;
    int EF_SPARC_LEDATA = 0x800000; /* little endian data */
    int EF_SPARC_32PLUS = 0x000100; /* generic V8+ features */
    int EF_SPARC_SUN_US1 = 0x000200; /* Sun UltraSPARC1 extensions */
    int EF_SPARC_HAL_R1 = 0x000400; /* HAL R1 extensions */
    int EF_SPARC_SUN_US3 = 0x000800; /* Sun UltraSPARCIII extensions */

    /* MIPS R3000 specific definitions. */
    int EF_MIPS_NOREORDER = 1; /* A .noreorder directive was used. */
    int EF_MIPS_PIC = 2; /* Contains PIC code. */
    int EF_MIPS_CPIC = 4; /* Uses PIC calling sequence. */
    int EF_MIPS_XGOT = 8;
    int EF_MIPS_64BIT_WHIRL = 16;
    int EF_MIPS_ABI2 = 32;
    int EF_MIPS_ABI_ON32 = 64;
    int EF_MIPS_NAN2008 = 1024; /* Uses IEEE 754-2008 NaN encoding. */
    int EF_MIPS_ARCH_1 = 0x00000000; /* -mips1 code. */
    int EF_MIPS_ARCH_2 = 0x10000000; /* -mips2 code. */
    int EF_MIPS_ARCH_3 = 0x20000000; /* -mips3 code. */
    int EF_MIPS_ARCH_4 = 0x30000000; /* -mips4 code. */
    int EF_MIPS_ARCH_5 = 0x40000000; /* -mips5 code. */
    int EF_MIPS_ARCH_32 = 0x50000000; /* MIPS32 code. */
    int EF_MIPS_ARCH_64 = 0x60000000; /* MIPS64 code. */
    int EF_MIPS_ARCH_32R2 = 0x70000000; /* MIPS32r2 code. */
    int EF_MIPS_ARCH_64R2 = 0x80000000; /* MIPS64r2 code. */

    /* HPPA specific definitions. */
    int EF_PARISC_TRAPNIL = 0x00010000; /* Trap nil pointer dereference. */
    int EF_PARISC_EXT = 0x00020000; /* Program uses arch. extensions. */
    int EF_PARISC_LSB = 0x00040000; /* Program expects little endian. */
    int EF_PARISC_WIDE = 0x00080000; /* Program expects wide mode. */
    int EF_PARISC_NO_KABP = 0x00100000; /* No kernel assisted branch prediction. */
    int EF_PARISC_LAZYSWAP = 0x00400000; /* Allow lazy swapping. */
    int EF_PARISC_ARCH_1_0 = 0x020b; /* PA-RISC 1.0 big-endian. */
    int EF_PARISC_ARCH_1_1 = 0x0210; /* PA-RISC 1.1 big-endian. */
    int EF_PARISC_ARCH_2_0 = 0x0214; /* PA-RISC 2.0 big-endian. */

    /* Alpha specific definitions. */
    int EF_ALPHA_32BIT = 1; /* All addresses must be < 2GB. */
    int EF_ALPHA_CANRELAX = 2; /* Relocations for relaxing exist. */

    /* PowerPC specific declarations */
    int EF_PPC_EMB = 0x80000000; /* PowerPC embedded flag */
    int EF_PPC_RELOCATABLE = 0x00010000; /* PowerPC -mrelocatable flag */
    int EF_PPC_RELOCATABLE_LIB = 0x00008000; /* PowerPC -mrelocatable-lib */

    /* ARM specific declarations */
    int EF_ARM_RELEXEC = 0x01;
    int EF_ARM_HASENTRY = 0x02;
    int EF_ARM_INTERWORK = 0x04;
    int EF_ARM_APCS_26 = 0x08;
    int EF_ARM_APCS_FLOAT = 0x10;
    int EF_ARM_PIC = 0x20;
    int EF_ARM_ALIGN8 = 0x40; /* 8-bit structure alignment is in use */
    int EF_ARM_NEW_ABI = 0x80;
    int EF_ARM_OLD_ABI = 0x100;
    int EF_ARM_SOFT_FLOAT = 0x200;
    int EF_ARM_VFP_FLOAT = 0x400;
    int EF_ARM_MAVERICK_FLOAT = 0x800;
    /* Other constants defined in the ARM ELF spec. version B-01. */
    /* NB. These conflict with values defined above. */
    int EF_ARM_SYMSARESORTED = 0x04;
    int EF_ARM_DYNSYMSUSESEGIDX = 0x08;
    int EF_ARM_MAPSYMSFIRST = 0x10;
    /* Constants defined in AAELF. */
    int EF_ARM_BE8 = 0x00800000;
    int EF_ARM_LE8 = 0x00400000;

    int EF_ARM_EABI_UNKNOWN = 0x00000000;
    int EF_ARM_EABI_VER1 = 0x01000000;
    int EF_ARM_EABI_VER2 = 0x02000000;
    int EF_ARM_EABI_VER3 = 0x03000000;
    int EF_ARM_EABI_VER4 = 0x04000000;
    int EF_ARM_EABI_VER5 = 0x05000000;

    /* IA-64 specific declarations. */
    int EF_IA_64_MASKOS = 0x0000000f; /* os-specific flags */
    int EF_IA_64_ABI64 = 0x00000010; /* 64-bit ABI */
    int EF_IA_64_ARCH = 0xff000000; /* arch. version mask */

    /* SH specific declarations */
    int EF_SH_MACH_MASK = 0x1f;
    int EF_SH_UNKNOWN = 0x0;
    int EF_SH1 = 0x1;
    int EF_SH2 = 0x2;
    int EF_SH3 = 0x3;
    int EF_SH_DSP = 0x4;
    int EF_SH3_DSP = 0x5;
    int EF_SH4AL_DSP = 0x6;
    int EF_SH3E = 0x8;
    int EF_SH4 = 0x9;
    int EF_SH2E = 0xb;
    int EF_SH4A = 0xc;
    int EF_SH2A = 0xd;
    int EF_SH4_NOFPU = 0x10;
    int EF_SH4A_NOFPU = 0x11;
    int EF_SH4_NOMMU_NOFPU = 0x12;
    int EF_SH2A_NOFPU = 0x13;
    int EF_SH3_NOMMU = 0x14;
    int EF_SH2A_SH4_NOFPU = 0x15;
    int EF_SH2A_SH3_NOFPU = 0x16;
    int EF_SH2A_SH4 = 0x17;
    int EF_SH2A_SH3E = 0x18;

    /* S/390 specific definitions. */
    int EF_S390_HIGH_GPRS = 0x00000001; /* High GPRs kernel facility needed. */
}
