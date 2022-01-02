/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.coff;


/**
 * Represents the name/type of a section in a COFF file.
 */
public class SectionType
{
  public final static SectionType TEXT = new SectionType( ".text" );
  public final static SectionType INIT = new SectionType( ".init" );
  public final static SectionType FINI = new SectionType( ".fini" );
  public final static SectionType RCONST = new SectionType( ".rconst" );
  public final static SectionType RDATA = new SectionType( ".rdata" );
  public final static SectionType DATA = new SectionType( ".data" );
  public final static SectionType BSS = new SectionType( ".bss" );
  public final static SectionType COMMENT = new SectionType( ".comment" );
  public final static SectionType LIB = new SectionType( ".lib" );

  private static final SectionType[] VALUES = { TEXT, INIT, FINI, RCONST, RDATA, DATA, BSS, COMMENT, LIB };

  private final String name;

  public SectionType( String name )
  {
    this.name = name;
  }

  public static SectionType valueOf( byte[] name )
  {
    String _name = new String( name );
    for ( SectionType value : VALUES )
    {
      if ( _name.equals( value.name ) )
      {
        return value;
      }
    }
    return new SectionType( _name );
  }

  @Override
  public String toString()
  {
    return name;
  }
}
