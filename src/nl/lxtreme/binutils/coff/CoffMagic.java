/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.coff;


/**
 * Identifies the state of the image file.
 */
public enum CoffMagic
{
  /** */
  STMAGIC( 0401 ),
  /** */
  OMAGIC( 0404 ),
  /** */
  JMAGIC( 0407 ),
  /** */
  DMAGIC( 0410 ),
  /** Also PE32 */
  ZMAGIC( 0413 ),
  /** */
  SHMAGIC( 0443 ),
  /** PE32+ */
  PE32_PLUS( 01013 );

  private final int no;

  private CoffMagic( int no )
  {
    this.no = no;
  }

  public static CoffMagic valueOf( int no )
  {
    for ( CoffMagic entry : values() )
    {
      if ( entry.no == no )
      {
        return entry;
      }
    }
    throw new IllegalArgumentException( "Invalid CoffMagic: 0" + Integer.toOctalString( no ) );
  }
}
