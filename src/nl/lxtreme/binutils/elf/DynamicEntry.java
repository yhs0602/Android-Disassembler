/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Represents an entry in the dynamic table.
 */
public class DynamicEntry {

    public static class Tag {
        public static final Tag NULL = new Tag(0, "Marks end of dynamic section");
        public static final Tag NEEDED = new Tag(1, "Name of needed library", true /* strTableOffset */);
        public static final Tag PLTRELSZ = new Tag(2, "Size in bytes of PLT relocs");
        public static final Tag PLTGOT = new Tag(3, "Processor defined value");
        public static final Tag HASH = new Tag(4, "Address of symbol hash table");
        public static final Tag STRTAB = new Tag(5, "Address of string table");
        public static final Tag SYMTAB = new Tag(6, "Address of symbol table");
        public static final Tag RELA = new Tag(7, "Address of Rela relocs");
        public static final Tag RELASZ = new Tag(8, "Total size of Rela relocs");
        public static final Tag RELAENT = new Tag(9, "Size of one Rela reloc");
        public static final Tag STRSZ = new Tag(10, "Size of string table");
        public static final Tag SYMENT = new Tag(11, "Size of one symbol table entry");
        public static final Tag INIT = new Tag(12, "Address of init function");
        public static final Tag FINI = new Tag(13, "Address of termination function");
        public static final Tag SONAME = new Tag(14, "Name of shared object", true /* strTableOffset */);
        public static final Tag RPATH = new Tag(15, "Library search path (deprecated)", true /* strTableOffset */);
        public static final Tag SYMBOLIC = new Tag(16, "Start symbol search here");
        public static final Tag REL = new Tag(17, "Address of Rel relocs");
        public static final Tag RELSZ = new Tag(18, "Total size of Rel relocs");
        public static final Tag RELENT = new Tag(19, "Size of one Rel reloc");
        public static final Tag PLTREL = new Tag(20, "Type of reloc in PLT");
        public static final Tag DEBUG = new Tag(21, "For debugging; unspecified");
        public static final Tag TEXTREL = new Tag(22, "Reloc might modify .text");
        public static final Tag JMPREL = new Tag(23, "Address of PLT relocs");
        public static final Tag BIND_NOW = new Tag(24, "Process relocations of object");
        public static final Tag INIT_ARRAY = new Tag(25, "Array with addresses of init fct");
        public static final Tag FINI_ARRAY = new Tag(26, "Array with addresses of fini fct");
        public static final Tag INIT_ARRAYSZ = new Tag(27, "Size in bytes of DT_INIT_ARRAY");
        public static final Tag FINI_ARRAYSZ = new Tag(28, "Size in bytes of DT_FINI_ARRAY");
        public static final Tag RUNPATH = new Tag(29, "Library search path");
        public static final Tag FLAGS = new Tag(30, "Flags for the object being loaded");
        public static final Tag ENCODING = new Tag(32, "Start of encoded range");
        public static final Tag PREINIT_ARRAY = new Tag(32, "Array with addresses of preinit fct");
        public static final Tag PREINIT_ARRAYSZ = new Tag(33, "size in bytes of DT_PREINIT_ARRAY");

        public static final Tag GNU_PRELINKED = new Tag(0x6ffffdf5, "Prelinking timestamp");
        public static final Tag GNU_CONFLICTSZ = new Tag(0x6ffffdf6, "Size of conflict section");
        public static final Tag GNU_LIBLISTSZ = new Tag(0x6ffffdf7, "Size of library list");
        public static final Tag CHECKSUM = new Tag(0x6ffffdf8, "CHECKSUM");
        public static final Tag PLTPADSZ = new Tag(0x6ffffdf9, "DT_PLTPADSZ");
        public static final Tag MOVEENT = new Tag(0x6ffffdfa, "DT_MOVEENT");
        public static final Tag MOVESZ = new Tag(0x6ffffdfb, "DT_MOVESZ");
        public static final Tag FEATURE_1 = new Tag(0x6ffffdfc, "DT_FEATURE_1");
        public static final Tag POSFLAG_1 = new Tag(0x6ffffdfd, "DT_POSFLAG_1");
        public static final Tag SYMINSZ = new Tag(0x6ffffdfe, "DT_SYMINSZ");

        public static final Tag GNU_HASH = new Tag(0x6ffffef5, "GNU-style hash table");
        public static final Tag TLSDESC_PLT = new Tag(0x6ffffef6, "DT_TLSDESC_PLT");
        public static final Tag TLSDESC_GOT = new Tag(0x6ffffef7, "DT_TLSDESC_GOT");
        public static final Tag GNU_CONFLICT = new Tag(0x6ffffef8, "Start of conflict section");
        public static final Tag GNU_LIBLIST = new Tag(0x6ffffef9, "Library list");
        public static final Tag CONFIG = new Tag(0x6ffffefa, "Configuration information");
        public static final Tag DEPAUDIT = new Tag(0x6ffffefb, "Dependency auditing");
        public static final Tag AUDIT = new Tag(0x6ffffefc, "Object auditing.");
        public static final Tag PLTPAD = new Tag(0x6ffffefd, "PLT padding");
        public static final Tag MOVETAB = new Tag(0x6ffffefe, "Move table");
        public static final Tag SYMINFO = new Tag(0x6ffffeff, "Syminfo table");

        public static final Tag VERSYM = new Tag(0x6ffffff0, "DT_VERSYM");
        public static final Tag RELACOUNT = new Tag(0x6ffffff9, "DT_RELACOUNT");
        public static final Tag RELCOUNT = new Tag(0x6ffffffa, "DT_RELCOUNT");
        public static final Tag FLAGS_1 = new Tag(0x6ffffffb, "State flags");
        public static final Tag VERDEF = new Tag(0x6ffffffc, "Address of version definition table");
        public static final Tag VERDEFNUM = new Tag(0x6ffffffd, "Number of version definitions");
        public static final Tag VERNEED = new Tag(0x6ffffffe, "Address of table with needed versions");
        public static final Tag VERNEEDNUM = new Tag(0x6fffffff, "Number of needed versions");

        private static final Tag[] VALUES =
            { NULL, NEEDED, PLTRELSZ, PLTGOT, HASH, STRTAB, SYMTAB, RELA, RELASZ, RELAENT, STRSZ, SYMENT, INIT, FINI,
                SONAME, RPATH, SYMBOLIC, REL, RELSZ, RELENT, PLTREL, DEBUG, TEXTREL, JMPREL, BIND_NOW, INIT_ARRAY,
                FINI_ARRAY, INIT_ARRAYSZ, FINI_ARRAYSZ, RUNPATH, FLAGS, ENCODING, PREINIT_ARRAY, PREINIT_ARRAYSZ,
                GNU_PRELINKED, GNU_CONFLICTSZ, GNU_LIBLISTSZ, CHECKSUM, PLTPADSZ, MOVEENT, MOVESZ, FEATURE_1, POSFLAG_1,
                SYMINSZ, GNU_HASH, TLSDESC_PLT, TLSDESC_GOT, GNU_CONFLICT, GNU_LIBLIST, CONFIG, DEPAUDIT, AUDIT, PLTPAD,
                MOVETAB, SYMINFO, VERSYM, RELACOUNT, RELCOUNT, FLAGS_1, VERDEF, VERDEFNUM, VERNEED, VERNEEDNUM };

        private static final int DT_LOOS = 0x6000000d;
        private static final int DT_HIOS = 0x6fffffff;
        private static final int DT_LOPROC = 0x70000000;
        private static final int DT_HIPROC = 0x7fffffff;

        public static Tag valueOf(int value) {
            for (Tag t : VALUES) {
                if (t.no == value) {
                    return t;
                }
            }
            if (value >= DT_LOOS && value <= DT_HIOS) {
                return new Tag(value, "OS-specific tag");
            } else if (value >= DT_LOPROC && value <= DT_HIPROC) {
                return new Tag(value, "Processor-specific tag");
            } else {
                throw new IllegalArgumentException("Invalid/unknown tag: " + Integer.toHexString(value));
            }
        }

        private final int no;
        private final String desc;
        private final boolean strTableOffset;

        private Tag(int no, String desc) {
            this(no, desc, false);
        }

        private Tag(int no, String desc, boolean strTableOffset) {
            this.no = no;
            this.desc = desc;
            this.strTableOffset = strTableOffset;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }

            Tag other = (Tag) obj;
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

    private final Tag tag;
    private final long value;

    public DynamicEntry(Tag tag, long value) {
        this.tag = tag;
        this.value = value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        DynamicEntry other = (DynamicEntry) obj;
        return (tag == other.tag) && (value == other.value);
    }

    public Tag getTag() {
        return tag;
    }

    public long getValue() {
        return value;
    }

    public boolean isStringOffset() {
        return tag.strTableOffset;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + tag.hashCode();
        result = prime * result + (int) (value ^ (value >>> 32));
        return result;
    }

    @Override
    public String toString() {
        return String.format("%s[%x]", tag, value);
    }
}
