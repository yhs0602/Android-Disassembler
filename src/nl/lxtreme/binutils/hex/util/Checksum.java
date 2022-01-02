/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2017 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.hex.util;


/**
 * Provides two checksum algorithms commonly used in many HEX-files.
 */
public enum Checksum
{
  /** */
  ONES_COMPLEMENT
  {
    @Override
    public Checksummer instance( byte seed )
    {
      return new BaseChecksummer( seed )
      {
        @Override
        public byte getResult()
        {
          return ( byte )( ~this.sum );
        }
      };
    }
  },
  /** */
  TWOS_COMPLEMENT
  {
    @Override
    public Checksummer instance( byte seed )
    {
      return new BaseChecksummer( seed )
      {
        @Override
        public byte getResult()
        {
          return ( byte )( ~this.sum + 1 );
        }
      };
    }
  };

  // METHODS

  /**
   * @return a new instance, cannot be <code>null</code>.
   */
  public final Checksummer instance()
  {
    return instance( ( byte )0 );
  }

  /**
   * @param seed
   *          the initial value to use for the checksum calculation.
   * @return a new instance, cannot be <code>null</code>.
   */
  public abstract Checksummer instance( byte seed );

  /**
   * Base implementation of a {@link Checksummer} shared by the various specific
   * implementations.
   */
  static abstract class BaseChecksummer implements Checksummer
  {
    protected byte sum;

    public BaseChecksummer( byte seed )
    {
      this.sum = seed;
    }

    @Override
    public final Checksummer add( byte... aValues )
    {
      for ( byte value : aValues )
      {
        this.sum += value;
      }
      return this;
    }

    @Override
    public final Checksummer addWord( int value )
    {
      add( ( byte )( ( value >> 8 ) & 0xFF ) );
      add( ( byte )( value & 0xFF ) );
      return this;
    }

    @Override
    public final Checksummer reset()
    {
      this.sum = 0;
      return this;
    }
  }
}
