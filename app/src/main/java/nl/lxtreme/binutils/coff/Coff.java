/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.coff;


import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
//import java.nio.file.*;


/**
 * Represents a COFF file.
 * <p>
 * This class is <b>not</b> thread-safe!
 * </p>
 */
public class Coff implements Closeable {
    public final FileHeader fileHeader;
    public final OptionalHeader optHeader;
    public final SectionHeader[] sectionHeaders;
    public final Symbol[] symbols;

    private FileChannel channel;

    public Coff(File file) throws IOException {
        this((new RandomAccessFile(file.getAbsolutePath(), "r").getChannel()));/* FileChannel.open( file.toPath(), StandardOpenOption.READ */
    }

    public Coff(FileChannel channel) throws IOException {
        this.channel = channel;
        this.fileHeader = new FileHeader(channel);

        ByteBuffer buf = ByteBuffer.allocate(Math.max(40, fileHeader.optionalHeaderSize));
        buf.limit(fileHeader.optionalHeaderSize);
        buf.order(fileHeader.getByteOrder());
        readFully(channel, buf, "Unable to read optional header!");

        this.optHeader = new OptionalHeader(buf);

        buf.clear();
        buf.limit(40);

        this.sectionHeaders = new SectionHeader[fileHeader.sectionCount];
        for (int i = 0; i < sectionHeaders.length; i++) {
            readFully(channel, buf, "Unable to read section header #" + (i + 1));

            sectionHeaders[i] = new SectionHeader(buf);
        }

        byte[] stringTable = new byte[0];

        long stringPos = fileHeader.symbolFilePtr + (fileHeader.symbolCount * 18);
        if (stringPos > 0 && stringPos < channel.size()) {
            channel.position(stringPos);

            buf.clear();
            buf.limit(4);
            readFully(channel, buf, "Unable to read string table size!");

            int size = buf.getInt();

            ByteBuffer stringBuf = ByteBuffer.allocate(size);
            readFully(channel, stringBuf, "Unable to read string table!");

            stringTable = stringBuf.array();
        }

        buf.clear();
        buf.limit(18);

        this.symbols = new Symbol[fileHeader.symbolCount];
        for (int i = 0; i < symbols.length; i++) {
            readFully(channel, buf, "Unable to read symbol #" + (i + 1));

            symbols[i] = new Symbol(buf, stringTable);
        }
    }

    static void readFully(ReadableByteChannel ch, ByteBuffer buf, String errMsg) throws IOException {
        buf.rewind();
        int read = ch.read(buf);
        if (read != buf.limit()) {
            throw new IOException(errMsg + " Read only " + read + " of " + buf.limit() + " bytes!");
        }
        buf.flip();
    }

    static String getZString(byte[] buf, int offset) {
        int end = offset;
        while (end < buf.length && buf[end] != 0) {
            end++;
        }
        return new String(buf, offset, (end - offset));
    }

    @Override
    public void close() throws IOException {
        if (channel != null) {
            channel.close();
            channel = null;
        }
    }

    /**
     * Returns the line number information for the given section. The section
     * should represent a ".text" or other code section.
     *
     * @return an array of line number information, or an empty array if no such
     * information is present.
     */
    public LineNumber[] getLineNumbers(SectionHeader shdr) throws IOException {
        if (shdr == null) {
            throw new IllegalArgumentException("Header cannot be null!");
        }
        if (channel == null) {
            throw new IOException("ELF file is already closed!");
        }
        if (shdr.lineNumberOffset == 0 || shdr.lineNumberSize == 0) {
            // Nothing to do...
            return new LineNumber[0];
        }

        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.order(fileHeader.getByteOrder());

        channel.position(shdr.lineNumberOffset);

        LineNumber[] result = new LineNumber[shdr.lineNumberSize];
        for (int i = 0; i < result.length; i++) {
            readFully(channel, buf, "Unable to read line number information!");

            result[i] = new LineNumber(buf);
        }

        return result;
    }

    /**
     * Returns the relocation information for the given section. The section
     * should represent a ".text" or other code section.
     *
     * @return an array of relocation information, or an empty array if no such
     * information is present.
     */
    public RelocationInfo[] getRelocationInfo(SectionHeader shdr) throws IOException {
        if (shdr == null) {
            throw new IllegalArgumentException("Header cannot be null!");
        }
        if (channel == null) {
            throw new IOException("ELF file is already closed!");
        }
        if (shdr.relocTableOffset == 0 || shdr.relocTableSize == 0) {
            // Nothing to do...
            return new RelocationInfo[0];
        }

        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.order(fileHeader.getByteOrder());

        channel.position(shdr.relocTableOffset);

        RelocationInfo[] result = new RelocationInfo[shdr.relocTableSize];
        for (int i = 0; i < result.length; i++) {
            readFully(channel, buf, "Unable to read relocation information!");

            result[i] = new RelocationInfo(buf);
        }

        return result;
    }

    /**
     * Returns the actual section data (= executable code + initialized data) for
     * the given section header.
     *
     * @return a byte buffer from which the data can be read, never
     * <code>null</code>.
     */
    public ByteBuffer getSectionData(SectionHeader shdr) throws IOException {
        if (shdr == null) {
            throw new IllegalArgumentException("Header cannot be null!");
        }
        if (channel == null) {
            throw new IOException("ELF file is already closed!");
        }

        ByteBuffer buf = ByteBuffer.allocate(shdr.size);
        buf.order(fileHeader.getByteOrder());

        channel.position(shdr.dataOffset);
        readFully(channel, buf, "Unable to read section completely!");

        return buf;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("COFF ");
        sb.append(fileHeader).append("; ");
        sb.append(optHeader).append("\n");
        for (int i = 0; i < sectionHeaders.length; i++) {
            sb.append("\t").append(sectionHeaders[i]).append("\n");
        }
        return sb.toString();
    }
}
