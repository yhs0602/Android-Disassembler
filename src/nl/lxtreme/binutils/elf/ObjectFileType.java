/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

public final class ObjectFileType {
    public static final ObjectFileType NONE = new ObjectFileType(0, "no file type");
    public static final ObjectFileType REL = new ObjectFileType(1, "relocatable");
    public static final ObjectFileType EXEC = new ObjectFileType(2, "executable");
    public static final ObjectFileType DYN = new ObjectFileType(3, "shared object");
    public static final ObjectFileType CORE = new ObjectFileType(4, "core file");

    private static final ObjectFileType[] VALUES = { NONE, REL, EXEC, DYN, CORE };

    private static final int ET_LOOS = 0xfe00;
    private static final int ET_HIOS = 0xfeff;
    private static final int ET_LOPROC = 0xff00;
    private static final int ET_HIPROC = 0xffff;

    public static ObjectFileType valueOf(int value) {
        for (ObjectFileType oft : VALUES) {
            if (oft.type == value) {
                return oft;
            }
        }
        if (value >= ET_LOOS && value <= ET_HIOS) {
            return new ObjectFileType(value, "OS-specific object file");
        } else if (value >= ET_LOPROC && value <= ET_HIPROC) {
            return new ObjectFileType(value, "Processor-specific object file");
        } else {
            throw new IllegalArgumentException("Unknown object file type!");
        }
    }

    private final int type;
    private final String desc;

    private ObjectFileType(int type, String desc) {
        this.type = type;
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
        ObjectFileType other = (ObjectFileType) obj;
        return (type == other.type);
    }

    @Override
    public int hashCode() {
        return 37 + type;
    }

    public String name() {
        return desc;
    }

    public int ordinal() {
        return this.type;
    }

    @Override
    public String toString() {
        return desc;
    }
}
