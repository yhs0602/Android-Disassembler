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


public class RelocationInfo
{
  public final int virtualAddress;
  public final int symbolIndex;
  public final int type;

  public RelocationInfo( ByteBuffer buf ) throws IOException
  {
    virtualAddress = buf.getInt();
    symbolIndex = buf.getInt();
    type = buf.getShort();
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append( "virtualAddress = 0x" ).append( Integer.toHexString( virtualAddress ) );
    sb.append( ", symbolIndex = " ).append( symbolIndex );
    sb.append( ", type = " ).append( type );
    return sb.toString();
  }
}
