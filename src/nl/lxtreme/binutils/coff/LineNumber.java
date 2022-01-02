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


public class LineNumber
{
  public final int lineNumber;
  public final int type;

  public LineNumber( ByteBuffer buf ) throws IOException
  {
    type = buf.getInt();
    lineNumber = buf.getShort();
  }

  public boolean isSymbolIndex()
  {
    return lineNumber == 0;
  }

  public boolean isVirtualAddress()
  {
    return lineNumber != 0;
  }
}
