/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Represents a type of section used in an ELF object.
 */
public class SectionType {
    public static final SectionType NULL = new SectionType(0, "Section header table entry unused");
    public static final SectionType PROGBITS = new SectionType(1, "Program data");
    public static final SectionType SYMTAB = new SectionType(2, "Symbol table");
    public static final SectionType STRTAB = new SectionType(3, "String table");
    public static final SectionType RELA = new SectionType(4, "Relocation entries with addends");
    public static final SectionType HASH = new SectionType(5, "Symbol hash table");
    public static final SectionType DYNAMIC = new SectionType(6, "Dynamic linking information");
    public static final SectionType NOTE = new SectionType(7, "Notes");
    public static final SectionType NOBITS = new SectionType(8, "Program space with no data (bss)");
    public static final SectionType REL = new SectionType(9, "Relocation entries, no addends");
    public static final SectionType SHLIB = new SectionType(10, "Reserved");
    public static final SectionType DYNSYM = new SectionType(11, "Thread-local storage segment");
    public static final SectionType INIT_ARRAY = new SectionType(14, "Array of constructors");
    public static final SectionType FINI_ARRAY = new SectionType(15, "Array of destructors");
    public static final SectionType PREINIT_ARRAY = new SectionType(16, "Array of pre-constructors");
    public static final SectionType GROUP = new SectionType(17, "Section group");
    public static final SectionType SYMTAB_SHNDX = new SectionType(18, "Extended section indeces");
    public static final SectionType GNU_ATTRIBUTES = new SectionType(0x6ffffff5, "GNU object attributes");
    public static final SectionType GNU_HASH = new SectionType(0x6ffffff6, "GNU-style hash table");
    public static final SectionType GNU_LIBLIST = new SectionType(0x6ffffff7, "GNU Prelink library list");
    public static final SectionType CHECKSUM = new SectionType(0x6ffffff8, "Checksum for DSO content");
    public static final SectionType SUNW_MOVE = new SectionType(0x6ffffffa, "SUNW_MOVE");
    public static final SectionType SUNW_COMDAT = new SectionType(0x6ffffffb, "SUNW_COMDAT");
    public static final SectionType SUNW_SYMINFO = new SectionType(0x6ffffffc, "SUNW_SYMINFO");
    public static final SectionType GNU_VERDEF = new SectionType(0x6ffffffd, "GNU version definition section");
    public static final SectionType GNU_VERNEED = new SectionType(0x6ffffffe, "GNU version needs section");
    public static final SectionType GNU_VERSYM = new SectionType(0x6fffffff, "GNU version symbol table");

    private static final SectionType[] VALUES = { NULL, PROGBITS, SYMTAB, STRTAB, RELA, HASH, DYNAMIC, NOTE, NOBITS,
        REL, SHLIB, DYNSYM, INIT_ARRAY, FINI_ARRAY, PREINIT_ARRAY, GROUP, SYMTAB_SHNDX, GNU_ATTRIBUTES, GNU_HASH,
        GNU_LIBLIST, CHECKSUM, SUNW_MOVE, SUNW_COMDAT, SUNW_SYMINFO, GNU_VERDEF, GNU_VERNEED, GNU_VERSYM };

    private static final int SHT_LOOS = 0x60000000;
    private static final int SHT_HIOS = 0x6fffffff;
    private static final int SHT_LOPROC = 0x70000000;
    private static final int SHT_HIPROC = 0x7fffffff;
    private static final int SHT_LOUSER = 0x70000000;
    private static final int SHT_HIUSER = 0x7fffffff;

    public static SectionType valueOf(int value) {
        for (SectionType st : VALUES) {
            if (st.no == value) {
                return st;
            }
        }
        if (value >= SHT_LOOS && value <= SHT_HIOS) {
            return new SectionType(value, "OS-specific segment");
        } else if (value >= SHT_LOPROC && value <= SHT_HIPROC) {
            return new SectionType(value, "Processor-specific segment");
        } else if (value >= SHT_LOUSER && value <= SHT_HIUSER) {
            return new SectionType(value, "User-specific segment");
        }
        throw new IllegalArgumentException("Invalid segment type!");
    }

    private final int no;
    private final String desc;

    private SectionType(int no, String desc) {
        this.no = no;
        this.desc = desc;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        SectionType other = (SectionType) obj;
        return (no == other.no);
    }

    @Override
    public int hashCode() {
        return 37 + no;
    }

    public String name() {
        return desc;
    }

    public int ordinal() {
        return no;
    }

    @Override
    public String toString() {
        return desc;
    }
}
