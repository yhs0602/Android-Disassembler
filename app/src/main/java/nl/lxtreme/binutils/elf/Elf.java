/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.elf;


import android.util.Log;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.util.ArrayList;
import java.util.List;

import nl.lxtreme.binutils.elf.DynamicEntry.Tag;


/**
 * Represents an ELF object file.
 * <p>
 * This class is <b>not</b> thread-safe!
 * </p>
 */
public class Elf implements Closeable {
    static int expectByteInRange(int in, int lowInclusive, int highInclusive, String errMsg) throws IOException {
        if (in < lowInclusive || in > highInclusive) {
            throw new IOException(errMsg);
        }
        return in;
    }

    public static String getZString(byte[] buf, long offset) {
        return getZString(buf, (int) (offset & 0xFFFFFFFF));
    }

    static String getZString(byte[] buf, int offset) {
        int end = offset;
        while (end < buf.length && buf[end] != 0) {
            end++;
        }
        return new String(buf, offset, (end - offset));
    }

    static boolean isBitSet(int flags, int mask) {
        return (flags & mask) == mask;
    }

    static boolean isBitSet(long flags, long mask) {
        return (flags & mask) == mask;
    }

    static void readFully(ReadableByteChannel ch, ByteBuffer buf, String errMsg) throws IOException {
        buf.rewind();
        int read = ch.read(buf);
        if (read != buf.limit()) {
            throw new IOException(errMsg + " Read only " + read + " of " + buf.limit() + " bytes!");
        }
        buf.flip();
    }

    public final Header header;
    public final ProgramHeader[] programHeaders;
    public final SectionHeader[] sectionHeaders;
    public final DynamicEntry[] dynamicTable;

    // locally managed.
    private FileChannel channel;

    public Elf(File file) throws IOException {
        this((new RandomAccessFile(file.getAbsolutePath(), "r").getChannel()));/* FileChannel.open( file.toPath(), StandardOpenOption.READ */
        /* FileChannel.open( file.toPath(), StandardOpenOption.READ*/
    }

    public Elf(FileChannel channel) throws IOException {
        this.channel = channel;
        this.header = new Header(channel);

        // Read the last part of the ELF header and interpret the various headers...
        ByteBuffer buf = ByteBuffer.allocate(65536);
        buf.order(header.elfByteOrder);
        buf.limit(10);

        readFully(channel, buf, "Unable to read entry information!");

        int programHeaderEntrySize = buf.getShort();
        int programHeaderEntryCount = buf.getShort();
        int sectionHeaderEntrySize = buf.getShort();
        int sectionHeaderEntryCount = buf.getShort();
        int sectionNameTableIndex = buf.getShort();

        // Should not be necessary unless we've not read the entire header...
        channel.position(header.programHeaderOffset);

        // Prepare for reading the program headers...
        buf.limit(programHeaderEntrySize);

        this.programHeaders = new ProgramHeader[programHeaderEntryCount];
        for (int i = 0; i < programHeaderEntryCount; i++) {
            readFully(channel, buf, "Unable to read program header entry #" + i);

            this.programHeaders[i] = new ProgramHeader(header.elfClass, buf);
        }

        // Should not be necessary unless we've not read the entire header...
        channel.position(header.sectionHeaderOffset);

        // Prepare for reading the section headers...
        buf.limit(sectionHeaderEntrySize);

        this.sectionHeaders = new SectionHeader[sectionHeaderEntryCount - 1];
        for (int i = 0; i < sectionHeaderEntryCount; i++) {
            readFully(channel, buf, "Unable to read section header entry #" + i);

            SectionHeader sHdr = new SectionHeader(header.elfClass, buf);
            if (i == 0) {
                // Should always be a SHT_NONE entry...
                if (sHdr.type != SectionType.NULL) {
                    throw new IOException("Invalid section found! First section should always be of type SHT_NULL!");
                }
            } else {
                this.sectionHeaders[i - 1] = sHdr;
            }
        }

        if (sectionNameTableIndex != 0) {
            // There's a section name string table present...
            SectionHeader shdr = this.sectionHeaders[sectionNameTableIndex - 1];

            buf = getSection(shdr);
            if (buf == null) {
                throw new IOException("Unable to get section name table!");
            }

            for (SectionHeader hdr : sectionHeaders) {
                hdr.setName(buf);
            }
        }

        ProgramHeader phdr = getProgramHeaderByType(SegmentType.DYNAMIC);
        if (phdr != null) {
            List<DynamicEntry> entries = new ArrayList<>();

            buf = getSegment(phdr);
            if (buf == null) {
                throw new IOException("Unable to get dynamic segment!");
            }

            // Walk through the entries...
            final boolean is32bit = header.is32bit();
            while (buf.remaining() > 0) {
                long tagValue = is32bit ? buf.getInt() : buf.getLong();
                long value = is32bit ? buf.getInt() : buf.getLong();
                if (tagValue == 0) {
                    break;
                }
                Tag tag = Tag.valueOf((int) tagValue);

                entries.add(new DynamicEntry(tag, value));
            }

            dynamicTable = entries.toArray(new DynamicEntry[entries.size()]);
        } else {
            dynamicTable = null;
        }
    }

    public Elf(String name) throws IOException {
        this(new File(name));
    }

    @Override
    public void close() throws IOException {
        if (channel != null) {
            channel.close();
            channel = null;
        }
    }

    protected StringBuilder dumpDynamicEntry(StringBuilder sb, DynamicEntry entry, byte[] stringTable) {
        sb.append(entry.getTag());
        sb.append(" => ");
        if (entry.isStringOffset()) {
            sb.append(getZString(stringTable, entry.getValue()));
        } else {
            sb.append("0x").append(Long.toHexString(entry.getValue()));
        }
        return sb;
    }

    protected StringBuilder dumpProgramHeader(StringBuilder sb, ProgramHeader phdr) {
        sb.append(phdr.type);
        sb.append(", offset: 0x").append(Long.toHexString(phdr.offset));
        sb.append(", vaddr: 0x").append(Long.toHexString(phdr.virtualAddress));
        sb.append(", paddr: 0x").append(Long.toHexString(phdr.physicalAddress));
        sb.append(", align: 0x").append(Long.toHexString(phdr.segmentAlignment));
        sb.append(", file size: 0x").append(Long.toHexString(phdr.segmentFileSize));
        sb.append(", memory size: 0x").append(Long.toHexString(phdr.segmentMemorySize));
        sb.append(", flags: ");
        if (isBitSet(phdr.flags, 0x04)) {
            sb.append("r");
        } else {
            sb.append("-");
        }
        if (isBitSet(phdr.flags, 0x02)) {
            sb.append("w");
        } else {
            sb.append("-");
        }
        if (isBitSet(phdr.flags, 0x01)) {
            sb.append("x");
        } else {
            sb.append("-");
        }
        return sb;
    }

    protected StringBuilder dumpSectionHeader(StringBuilder sb, SectionHeader shdr) {
        String name = shdr.getName();
        if (name != null) {
            sb.append(name);
            sb.append("\t");
            sb.append(shdr.type);
        } else {
            sb.append(shdr.type);
        }
        sb.append(", size: 0x").append(Long.toHexString(shdr.size));
        sb.append(", vaddr: 0x").append(Long.toHexString(shdr.virtualAddress));
        sb.append(", foffs: 0x").append(Long.toHexString(shdr.fileOffset));
        sb.append(", align: 0x").append(Long.toHexString(shdr.sectionAlignment));
        if (shdr.link != 0) {
            sb.append(", link: 0x").append(Long.toHexString(shdr.link));
        }
        if (shdr.info != 0) {
            sb.append(", info: 0x").append(Long.toHexString(shdr.info));
        }
        if (shdr.entrySize != 0) {
            sb.append(", entrySize: 0x").append(Long.toHexString(shdr.entrySize));
        }
        return sb;
    }

    public byte[] getDynamicSymbolTable() throws IOException {
        SectionHeader dynSymHdr = getSectionHeaderByType(SectionType.SYMTAB);
        if (dynSymHdr == null) {
            throw new IOException("Unable to get symbol table for dynamic section!");
        }

        ByteBuffer dynSym = getSection(dynSymHdr);
        if (dynSym == null) {
            throw new IOException("Unable to get symbol table for dynamic section!");
        }

        return dynSym.array();
    }

    public byte[] getDynamicStringTable() throws IOException {
        SectionHeader dynStrHdr = getSectionHeaderByType(SectionType.STRTAB);
        if (dynStrHdr == null) {
            throw new IOException("Unable to get string table for dynamic section!");
        }

        ByteBuffer dynStr = getSection(dynStrHdr);
        if (dynStr == null) {
            throw new IOException("Unable to get string table for dynamic section!");
        }

        return dynStr.array();
    }

    /**
     * Returns the first program header with the given type.
     *
     * @return the first program header with the given type, or <code>null</code>
     * if no such segment exists in this ELF object.
     */
    public ProgramHeader getProgramHeaderByType(SegmentType type) {
        if (type == null) {
            throw new IllegalArgumentException("Type cannot be null!");
        }
        for (ProgramHeader hdr : programHeaders) {
            if (type.equals(hdr.type)) {
                return hdr;
            }
        }
        return null;
    }

    /**
     * Convenience method for determining which interpreter should be used for
     * this ELF object.
     *
     * @return the name of the interpreter, or <code>null</code> if no interpreter
     * could be determined.
     */
    public String getProgramInterpreter() throws IOException {
        ProgramHeader phdr = getProgramHeaderByType(SegmentType.INTERP);
        if (phdr == null) {
            return null;
        }

        ByteBuffer buf = getSegment(phdr);
        if (buf == null) {
            throw new IOException("Unable to get program interpreter segment?!");
        }

        return new String(buf.array(), 0, buf.remaining());
    }

    /**
     * Returns the actual section data based on the information from the given
     * header.
     *
     * @return a byte buffer from which the section data can be read, never
     * <code>null</code>.
     */
    public ByteBuffer getSection(SectionHeader shdr) throws IOException {
        if (shdr == null) {
            throw new IllegalArgumentException("Header cannot be null!");
        }
        if (channel == null) {
            throw new IOException("ELF file is already closed!");
        }

        ByteBuffer buf = ByteBuffer.allocate((int) shdr.size);
        buf.order(header.elfByteOrder);

        channel.position(shdr.fileOffset);
        readFully(channel, buf, "Unable to read section completely!");

        return buf;
    }

    /**
     * Returns the first section header with the given type.
     *
     * @return the first section header with the given type, or <code>null</code>
     * if no such section exists in this ELF object.
     */
    public SectionHeader getSectionHeaderByType(SectionType type) {
        if (type == null) {
            throw new IllegalArgumentException("Type cannot be null!");
        }
        for (SectionHeader hdr : sectionHeaders) {
            if (type.equals(hdr.type)) {
                return hdr;
            }
        }
        return null;
    }

    /**
     * Returns the actual segment data based on the information from the given
     * header.
     *
     * @return a {@link ByteBuffer} from which the segment data can be read, never
     * <code>null</code>.
     */
    public ByteBuffer getSegment(final ProgramHeader phdr) throws IOException {
        if (phdr == null) {
            throw new IllegalArgumentException("Header cannot be null!");
        }
        if (channel == null) {
            throw new IOException("ELF file is already closed!");
        }

        ByteBuffer buf = ByteBuffer.allocate((int) phdr.segmentFileSize);
        buf.order(header.elfByteOrder);

        channel.position(phdr.offset);
        readFully(channel, buf, "Unable to read segment completely!");

        return buf;
    }

    public List<String> getSharedDependencies() throws IOException {
        byte[] array = getDynamicStringTable();

        List<String> result = new ArrayList<>();
        for (DynamicEntry entry : dynamicTable) {
            if (Tag.NEEDED.equals(entry.getTag())) {
                result.add(getZString(array, (int) entry.getValue()));
            }
        }

        return result;
    }

    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(header).append('\n');
            sb.append("Program header:\n");
            for (int i = 0; i < programHeaders.length; i++) {
                sb.append('\t');
                dumpProgramHeader(sb, programHeaders[i]);
                sb.append('\n');
            }

            byte[] strTable = getDynamicStringTable();

            sb.append("Dynamic table:\n");
            if (dynamicTable != null)
                for (DynamicEntry entry : dynamicTable) {
                    sb.append('\t');
                    dumpDynamicEntry(sb, entry, strTable);
                    sb.append('\n');
                }

            sb.append("Sections:\n");
            for (int i = 0; i < sectionHeaders.length; i++) {
                SectionHeader shdr = sectionHeaders[i];
                if (!SectionType.STRTAB.equals(shdr.type)) {
                    sb.append('\t');
                    dumpSectionHeader(sb, sectionHeaders[i]);
                    sb.append('\n');
                }
            }
            return sb.toString();
        } catch (IOException exception) {
            throw new RuntimeException("Unable to get dynamic string table!");
        } catch (NullPointerException npe) {
            Log.e("Disassembler elf", "", npe);
        }
        return "";
    }
}
