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


public class Symbol
{
  public static final int DEBUG = 2;
  public static final int ABSOLUTE = 1;
  public static final int NONE = 0;

  public final String name;
  public final int value;
  public final int sectionNumber;
  public final int type;
  public final int storageClass;
  public final int auxCount;

  public Symbol( ByteBuffer buf, byte[] stringTable ) throws IOException
  {
    byte[] nameBuf = new byte[8];
    buf.get( nameBuf );

    if ( nameBuf[0] == 0 && nameBuf[1] == 0 && nameBuf[2] == 0 && nameBuf[3] == 0 )
    {
      // Long name (> 8 characters)...
      int offset = ( ( ( nameBuf[7] & 0xff ) << 24 ) | ( ( nameBuf[6] & 0xff ) << 16 ) | ( ( nameBuf[5] & 0xff ) << 8 )
          | ( nameBuf[4] & 0xff ) ) - 4;
      if ( offset > 0 && offset < stringTable.length )
      {
        name = getZString( stringTable, offset );
      }
      else
      {
        name = "";
      }
    }
    else
    {
      name = new String( nameBuf );
    }

    value = buf.getInt();
    sectionNumber = buf.getShort();
    type = buf.getShort();
    storageClass = buf.get();
    auxCount = buf.getInt();
  }

  public boolean isAbsoluteSymbol()
  {
    return sectionNumber == ABSOLUTE;
  }

  public boolean isDebugSymbol()
  {
    return sectionNumber == DEBUG;
  }

  public boolean isExternal()
  {
    return sectionNumber == NONE;
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append( name );
    sb.append( ", value = 0x" ).append( Integer.toHexString( value ) );
    return sb.toString();
  }
}
