/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Represents the various known machine types (extracted from "elf.h" file from libc6-dev package).
 */
public enum MachineType {
    NONE(0, "No machine"),
    M32(1, "AT&T WE 32100"),
    SPARC(2, "SUN SPARC"),
    i386(3, "Intel 80386"),
    m68K(4, "Motorola m68k family"),
    m88K(5, "Motorola m88k family"),
    i860(7, "Intel 80860"),
    MIPS(8, "MIPS R3000 big-endian"),
    S370(9, "IBM System/370"),
    MIPS_RS3_LE(10, "MIPS R3000 little-endian"),

    PARISC(15, "HPPA"),
    VPP500(17, "Fujitsu VPP500"),
    SPARC32PLUS(18, "Sun's \"v8plus\""),
    i960(19, "Intel 80960"),
    PPC(20, "PowerPC"),
    PPC64(21, "PowerPC 64-bit"),
    S390(22, "IBM S390"),

    V800(36, "NEC V800 series"),
    FR20(37, "Fujitsu FR20"),
    RH32(38, "TRW RH-32"),
    RCE(39, "Motorola RCE"),
    ARM(40, "ARM"),
    FAKE_ALPHA(41, "Digital Alpha"),
    SH(42, "Hitachi SH"),
    SPARCV9(43, "SPARC v9 64-bit"),
    TRICORE(44, "Siemens Tricore"),
    ARC(45, "Argonaut RISC Core"),
    H8_300(46, "Hitachi H8/300"),
    H8_300H(47, "Hitachi H8/300H"),
    H8S(48, "Hitachi H8S"),
    H8_500(49, "Hitachi H8/500"),
    IA_64(50, "Intel Merced"),
    MIPS_X(51, "Stanford MIPS-X"),
    COLDFIRE(52, "Motorola Coldfire"),
    m68HC12(53, "Motorola M68HC12"),
    MMA(54, "Fujitsu MMA Multimedia Accelerator"),
    PCP(55, "Siemens PCP"),
    NCPU(56, "Sony nCPU embeeded RISC"),
    NDR1(57, "Denso NDR1 microprocessor"),
    STARCORE(58, "Motorola Start*Core processor"),
    ME16(59, "Toyota ME16 processor"),
    ST100(60, "STMicroelectronic ST100 processor"),
    TINYJ(61, "Advanced Logic Corp. Tinyj emb.fam"),
    x86_64(62, "x86-64"),
    PDSP(63, "Sony DSP Processor"),

    FX66(66, "Siemens FX66 microcontroller"),
    ST9PLUS(67, "STMicroelectronics ST9+ 8/16 mc"),
    ST7(68, "STmicroelectronics ST7 8 bit mc"),
    m68HC16(69, "Motorola MC68HC16 microcontroller"),
    m68HC11(70, "Motorola MC68HC11 microcontroller"),
    m68HC08(71, "Motorola MC68HC08 microcontroller"),
    m68HC05(72, "Motorola MC68HC05 microcontroller"),
    SVX(73, "Silicon Graphics SVx"),
    ST19(74, "STMicroelectronics ST19 8 bit mc"),
    VAX(75, "Digital VAX"),
    CRIS(76, "Axis Communications 32-bit embedded processor"),
    JAVELIN(77, "Infineon Technologies 32-bit embedded processor"),
    FIREPATH(78, "Element 14 64-bit DSP Processor"),
    ZSP(79, "LSI Logic 16-bit DSP Processor"),
    MMIX(80, "Donald Knuth's educational 64-bit processor"),
    HUANY(81, "Harvard University machine-independent object files"),
    PRISM(82, "SiTera Prism"),
    AVR(83, "Atmel AVR 8-bit microcontroller"),
    FR30(84, "Fujitsu FR30"),
    D10V(85, "Mitsubishi D10V"),
    D30V(86, "Mitsubishi D30V"),
    V850(87, "NEC v850"),
    M32R(88, "Mitsubishi M32R"),
    MN10300(89, "Matsushita MN10300"),
    MN10200(90, "Matsushita MN10200"),
    PJ(91, "picoJava"),
    OPENRISC(92, "OpenRISC 32-bit embedded processor"),
    ARC_A5(93, "ARC Cores Tangent-A5"),
    XTENSA(94, "Tensilica Xtensa Architecture"),
    AARCH64(183, "ARM AARCH64"),
    TILEPRO(188, "Tilera TILEPro"),
    MICROBLAZE(189, "Xilinx MicroBlaze"),
    TILEGX(191, "Tilera TILE-Gx");

    private final int no;
    private final String desc;

    private MachineType(int no, String desc) {
        this.no = no;
        this.desc = desc;
    }

    static MachineType valueOf(int value) {
        for (MachineType mt : values()) {
            if (mt.no == value) {
                return mt;
            }
        }
        throw new IllegalArgumentException("Invalid machine type: " + value);
    }

    @Override
    public String toString() {
        return desc;
    }
}