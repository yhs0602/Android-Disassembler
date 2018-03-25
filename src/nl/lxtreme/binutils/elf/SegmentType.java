/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Represents a type of segment used in an ELF object.
 */
public class SegmentType {
    public static final SegmentType NULL = new SegmentType(0, "Program header table entry unused");
    public static final SegmentType LOAD = new SegmentType(1, "Loadable program segment");
    public static final SegmentType DYNAMIC = new SegmentType(2, "Dynamic linking information");
    public static final SegmentType INTERP = new SegmentType(3, "Program interpreter");
    public static final SegmentType NOTE = new SegmentType(4, "Auxiliary information");
    public static final SegmentType SHLIB = new SegmentType(5, "Reserved");
    public static final SegmentType PHDR = new SegmentType(6, "Entry for header table itself");
    public static final SegmentType TLS = new SegmentType(7, "Thread-local storage segment");
    public static final SegmentType GNU_EH_FRAME = new SegmentType(0x6474e550, "GCC .eh_frame_hdr segment");
    public static final SegmentType GNU_STACK = new SegmentType(0x6474e551, "Stack executability");
    public static final SegmentType GNU_RELRO = new SegmentType(0x6474e552, "Read-only after relocation");
    public static final SegmentType SUNWBSS = new SegmentType(0x6ffffffa, "Sun Specific segment");
    public static final SegmentType SUNWSTACK = new SegmentType(0x6ffffffb, "Sun Stack segment");

    public static final SegmentType[] VALUES =
        { NULL, LOAD, DYNAMIC, INTERP, NOTE, SHLIB, PHDR, TLS, GNU_EH_FRAME, GNU_STACK, GNU_RELRO, SUNWBSS, SUNWSTACK };

    private static final int PT_LOOS = 0x60000000;
    private static final int PT_HIOS = 0x6fffffff;
    private static final int PT_LOPROC = 0x70000000;
    private static final int PT_HIPROC = 0x7fffffff;

    private final int no;
    private final String desc;

    private SegmentType(int no, String desc) {
        this.no = no;
        this.desc = desc;
    }

    public static SegmentType valueOf(int value) {
        for (SegmentType st : VALUES) {
            if (st.no == value) {
                return st;
            }
        }
        if (value >= PT_LOOS && value <= PT_HIOS) {
            return new SegmentType(value, "OS-specific segment");
        } else if (value >= PT_LOPROC && value <= PT_HIPROC) {
            return new SegmentType(value, "Processor-specific segment");
        }
        throw new IllegalArgumentException("Invalid segment type!");
    }

    public int ordinal() {
        return no;
    }

    public String name() {
        return desc;
    }

    @Override
    public String toString() {
        return desc;
    }
}
