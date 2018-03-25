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
 * Represents information about the various segments in an ELF object.
 */
public class ProgramHeader {
    public final SegmentType type;
    public final long flags;
    public final long offset;
    public final long virtualAddress;
    public final long physicalAddress;
    public final long segmentFileSize;
    public final long segmentMemorySize;
    public final long segmentAlignment;

    public ProgramHeader(ElfClass elfClass, ByteBuffer buf) throws IOException {
        switch (elfClass) {
            case CLASS_32:
                type = SegmentType.valueOf(buf.getInt() & 0xFFFFFFFF);
                offset = buf.getInt() & 0xFFFFFFFFL;
                virtualAddress = buf.getInt() & 0xFFFFFFFFL;
                physicalAddress = buf.getInt() & 0xFFFFFFFFL;
                segmentFileSize = buf.getInt() & 0xFFFFFFFFL;
                segmentMemorySize = buf.getInt() & 0xFFFFFFFFL;
                flags = buf.getInt() & 0xFFFFFFFFL;
                segmentAlignment = buf.getInt() & 0xFFFFFFFFL;
                break;
            case CLASS_64:
                type = SegmentType.valueOf(buf.getInt() & 0xFFFFFFFF);
                flags = buf.getInt() & 0xFFFFFFFFL;
                offset = buf.getLong();
                virtualAddress = buf.getLong();
                physicalAddress = buf.getLong();
                segmentFileSize = buf.getLong();
                segmentMemorySize = buf.getLong();
                segmentAlignment = buf.getLong();
                break;
            default:
                throw new IOException("Unhandled ELF-class!");
        }
    }
}