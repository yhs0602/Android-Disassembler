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


/**
 * Represents the a.out/optional header in a COFF file.
 */
public class OptionalHeader
{
  public final CoffMagic magic;
  public final int versionStamp;
  public final int textSize;
  public final int initDataSize;
  public final int uninitDataSize;
  public final int entryPoint;
  public final int textStart;
  public final int dataStart;

  public OptionalHeader( ByteBuffer buf ) throws IOException
  {
    magic = CoffMagic.valueOf( buf.getShort() );
    versionStamp = buf.getShort();
    textSize = buf.getInt();
    initDataSize = buf.getInt();
    uninitDataSize = buf.getInt();
    entryPoint = buf.getInt();
    textStart = buf.getInt();
    if ( buf.hasRemaining() )
    {
      dataStart = buf.getInt();
    }
    else
    {
      dataStart = -1;
    }
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append( magic );
    sb.append( ", entry point: 0x" ).append( Integer.toHexString( entryPoint ) );
    sb.append( ", code start: 0x" ).append( Integer.toHexString( textStart ) );
    sb.append( ", code size: " ).append( textSize );
    sb.append( ", data start: 0x" ).append( Integer.toHexString( dataStart ) );
    sb.append( ", data size: " ).append( initDataSize ).append( "+" ).append( uninitDataSize );
    return sb.toString();
  }
}
