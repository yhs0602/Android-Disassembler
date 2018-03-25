/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.coff;


import java.io.*;
import java.nio.*;


public class SectionHeader
{
  public static final int FLAG_REG = 0x00; // regular segment
  public static final int FLAG_DSECT = 0x01; // dummy segment
  public static final int FLAG_NOLOAD = 0x02; // no-load segment
  public static final int FLAG_GROUP = 0x04; // group segment
  public static final int FLAG_PAD = 0x08; // .pad segment
  public static final int FLAG_COPY = 0x10; // copy section
  public static final int FLAG_TEXT = 0x20; // .text segment (= executable code)
  public static final int FLAG_DATA = 0x40; // .data segment (= initialized
                                            // data)
  public static final int FLAG_BSS = 0x80; // .bss segment (= uninitialized
                                           // data)
  public static final int FLAG_INFO = 0x200; // .comment section
  public static final int FLAG_OVER = 0x400; // overlay section
  public static final int FLAG_LIB = 0x800; // library section

  public final SectionType type;
  public final int physicalAddress;
  public final int virtualAddress;
  public final int size;
  public final int dataOffset;
  public final int relocTableOffset;
  public final int relocTableSize;
  public final int lineNumberOffset;
  public final int lineNumberSize;
  public final int flags;

  public SectionHeader( ByteBuffer buf ) throws IOException
  {
    byte[] nameBytes = new byte[8];
    buf.get( nameBytes );

    type = SectionType.valueOf( nameBytes );
    physicalAddress = buf.getInt();
    virtualAddress = buf.getInt();
    size = buf.getInt();
    dataOffset = buf.getInt();
    relocTableOffset = buf.getInt();
    lineNumberOffset = buf.getInt();
    relocTableSize = buf.getShort();
    lineNumberSize = buf.getShort();
    flags = buf.getInt();
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append( type );
    sb.append( ", size = " ).append( size );
    if ( physicalAddress != virtualAddress )
    {
      sb.append( ", address (p/v) = 0x" ).append( Integer.toHexString( physicalAddress ) ).append( "/0x" ).append( Integer.toHexString( virtualAddress ) );
    }
    else
    {
      sb.append( ", address = 0x" ).append( Integer.toHexString( physicalAddress ) );
    }
    sb.append( ", flags = " ).append( flags );
    return sb.toString();
  }
}
