/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.coff;


public enum MachineType
{
  /** */
  UNKNOWN( 0, "Unknown" ),
  /** */
  ALPHA( 0x184, "Alpha AXP" ),
  /** */
  ARM( 0x1c0, "ARM" ),
  /** */
  ALPHA64( 0x284, "Alpha AXP-64" ),
  /** */
  I386( 0x14c, "i386 compatible" ),
  /** */
  IA64( 0x200, "Intel IA64" ),
  /** */
  M68K( 0x268, "m68k" ),
  /** */
  MIPS16( 0x266, "MIPS-16" ),
  /** */
  MIPS_FPU( 0x366, "MIPS with FPU" ),
  /** */
  MIPS_FPU16( 0x466, "MIPS-16 with FPU" ),
  /** */
  POWERPC( 0x1f0, "PowerPC little-endian" ),
  /** */
  R3000( 0x162, "MIPS R3000 little-endian" ),
  /** */
  R4000( 0x166, "MIPS R4000 little-endian" ),
  /** */
  R10000( 0x168, "MIPS R10000 little-endian" ),
  /** */
  SH3( 0x1a2, "Hitachi SH3" ),
  /** */
  SH4( 0x1a6, "Hitachi SH4" ),
  /** */
  THUMB( 0x1c2, "ARM thumb" );

  private final int no;
  private final String desc;

  private MachineType( int no, String desc )
  {
    this.no = no;
    this.desc = desc;
  }

  static MachineType valueOf( int value )
  {
    for ( MachineType mt : values() )
    {
      if ( mt.no == value )
      {
        return mt;
      }
    }
    throw new IllegalArgumentException( "Invalid machine type: " + value );
  }

  @Override
  public String toString()
  {
    return desc;
  }
}
