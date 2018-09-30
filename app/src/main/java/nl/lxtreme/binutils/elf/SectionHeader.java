/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

import java.io.*;
import java.nio.*;

/**
 * Represents information about the various sections in an ELF object.
 */
public class SectionHeader {
    private final int nameOffset;
    private String name;

    public final SectionType type;
    public final long flags;
    public final long virtualAddress;
    public final long fileOffset;
    public final long size;
    public final int link;
    public final int info;
    public final long sectionAlignment;
    public final long entrySize;

    public SectionHeader(ElfClass elfClass, ByteBuffer buf) throws IOException {
        nameOffset = buf.getInt();
        type = SectionType.valueOf(buf.getInt());

        if (elfClass == ElfClass.CLASS_32) {
            flags = buf.getInt() & 0xFFFFFFFFL;
            virtualAddress = buf.getInt() & 0xFFFFFFFFL;
            fileOffset = buf.getInt() & 0xFFFFFFFFL;
            size = buf.getInt() & 0xFFFFFFFFL;
        } else if (elfClass == ElfClass.CLASS_64) {
            flags = buf.getLong();
            virtualAddress = buf.getLong();
            fileOffset = buf.getLong();
            size = buf.getLong();
        } else {
            throw new IOException("Unhandled ELF-class!");
        }

        link = buf.getInt();
        info = buf.getInt();

        if (elfClass == ElfClass.CLASS_32) {
            sectionAlignment = buf.getInt() & 0xFFFFFFFFL;
            entrySize = buf.getInt() & 0xFFFFFFFFL;
        } else if (elfClass == ElfClass.CLASS_64) {
            sectionAlignment = buf.getLong();
            entrySize = buf.getLong();
        } else {
            throw new IOException("Unhandled ELF-class!");
        }
    }

    public String getName() {
        return name;
    }

    void setName(ByteBuffer buf) {
        if (nameOffset > 0) {
            byte[] array = buf.array();

            int end = nameOffset;
            while (end < array.length && array[end] != 0) {
                end++;
            }

            name = new String(array, nameOffset, end - nameOffset);
        }
    }
}
