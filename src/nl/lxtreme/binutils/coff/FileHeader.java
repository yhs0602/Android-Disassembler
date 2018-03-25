/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.coff;


import static nl.lxtreme.binutils.coff.Coff.*;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;


/**
 * Represents a COFF file header.
 */
public class FileHeader
{
  // relocation info stripped from file
  public static final int F_RELFLG = 0x0001;
  // file is executable (no unresolved external references)
  public static final int F_EXEC = 0x0002;
  // line numbers stripped from file
  public static final int F_LNNO = 0x0004;
  // local symbols stripped from file
  public static final int F_LSYMS = 0x0008;
  // Aggressively trim working set
  public static final int F_AGGRESSIVE_WS_TRIM = 0x0010;
  // App can handle >2GB addresses.
  public static final int F_LARGE_ADDRESS_AWARE = 0x0020;
  // Use of this flag is reserved for future use.
  public static final int F_FILE_16BIT_MACHINE = 0x0040;
  // file is 16-bit little-endian
  public static final int F_AR16WR = 0x0080;
  // file is 32-bit little-endian
  public static final int F_AR32WR = 0x0100;
  // file is 32-bit big-endian or debug information stripped.
  public static final int F_AR32W = 0x0200;
  // If image is on removable media, copy and run from swap file.
  public static final int F_REMOVABLE_RUN_FROM_SWAP = 0x0400;
  // rs/6000 aix: dynamically loadable w/imports & exports
  public static final int F_DYNLOAD = 0x1000;
  // rs/6000 aix: file is a shared object or PE format DLL.
  public static final int F_SHROBJ = 0x2000;
  // File should be run only on a UP machine.
  public static final int F_UP_SYSTEM_ONLY = 0x4000;
  // Big endian: MSB precedes LSB in memory.
  public static final int F_AR32BE = 0x8000;

  public final MachineType machineType;
  public final int sectionCount;
  public final long timestamp;
  public final long symbolFilePtr;
  public final int symbolCount;
  public final int optionalHeaderSize;
  public final int flags;

  public FileHeader( FileChannel channel ) throws IOException
  {
    final ByteBuffer buf = ByteBuffer.allocate( 20 );

    buf.order( ByteOrder.LITTLE_ENDIAN );
    readFully( channel, buf, "Unable to read file header!" );

    machineType = MachineType.valueOf( buf.getShort() );
    sectionCount = buf.getShort();
    timestamp = buf.getInt();
    symbolFilePtr = buf.getInt();
    symbolCount = buf.getInt();
    optionalHeaderSize = buf.getShort();
    flags = buf.getShort();
  }

  /**
   * @return <code>true</code> if the COFF file is stripped and has no symbols,
   *         <code>false</code> otherwise.
   */
  public boolean isStripped()
  {
    return symbolFilePtr == 0 && symbolCount == 0;
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append( machineType );
    if ( timestamp != 0 )
    {
      sb.append( "created at " ).append( timestamp );
    }
    if ( isStripped() )
    {
      sb.append( " (stripped)" );
    }
    else
    {
      sb.append( " (" ).append( symbolCount ).append( " symbols)" );
    }
    if ( flags != 0 )
    {
      sb.append( " flags = 0x" ).append( Integer.toHexString( flags ) );
    }
    return sb.toString();
  }

  public ByteOrder getByteOrder()
  {
    ByteOrder result = ByteOrder.LITTLE_ENDIAN;
    if ( ( flags & F_AR32BE ) != 0 || ( flags & F_AR32W ) != 0 )
    {
      result = ByteOrder.BIG_ENDIAN;
    }
    return result;
  }
}
