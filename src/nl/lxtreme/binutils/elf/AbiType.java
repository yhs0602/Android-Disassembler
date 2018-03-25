/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Represent the various types of ABIs that exist (extracted from "elf.h" file from libc6-dev package).
 */
public enum AbiType {
    SYSV(0, "UNIX System V ABI"),
    HPUX(1, "HP-UX"),
    NETBSD(2, "NetBSD."),
    GNU(3, "Object uses GNU ELF extensions."),
    SOLARIS(6, "Sun Solaris."),
    AIX(7, "IBM AIX."),
    IRIX(8, "SGI Irix."),
    FREEBSD(9, "FreeBSD."),
    TRU64(10, "Compaq TRU64 UNIX."),
    MODESTO(11, "Novell Modesto."),
    OPENBSD(12, "OpenBSD."),
    ARM_AEABI(64, "ARM EABI"),
    ARM(97, "ARM"),
    STANDALONE(255, "Standalone (embedded) application");

    private final int no;
    private final String desc;

    private AbiType(int no, String desc) {
        this.no = no;
        this.desc = desc;
    }

    static AbiType valueOf(int value) {
        for (AbiType at : values()) {
            if (at.no == value) {
                return at;
            }
        }
        throw new IllegalArgumentException("Invalid ABI type: " + value);
    }

    @Override
    public String toString() {
        return desc;
    }
}