/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2017 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.hex;


import java.io.*;
import java.nio.*;

import nl.lxtreme.binutils.hex.util.*;


/**
 * Base implementation for interpreting hex-based data files.
 */
public abstract class AbstractReader
{
  // VARIABLES

  protected final Reader reader;

  // CONSTRUCTORS

  /**
   * Creates a new AbstractReader instance.
   */
  public AbstractReader( Reader aReader )
  {
    this.reader = ( aReader instanceof BufferedReader ) ? ( BufferedReader )aReader : new BufferedReader( aReader );
  }

  // METHODS

  /**
   * Closes this instruction stream.
   *
   * @throws IOException
   *           in case of stream I/O problems.
   */
  public void close() throws IOException
  {
    this.reader.close();
  }

  /**
   * @return the current address location, or <tt>-1</tt> if no address is
   *         known.
   * @throws IOException
   *           in case of I/O problems.
   */
  public abstract long getAddress() throws IOException;

  /**
   * Reads a single byte from the underlying stream.
   *
   * @return the next byte, can be <code>-1</code> in case an end-of-stream was
   *         encountered.
   * @throws IOException
   *           in case of stream I/O problems;
   */
  public abstract int readByte() throws IOException;

  /**
   * Reads a long word (4 bytes) from the underlying stream.
   *
   * @return the next long word, can be <code>-1</code> in case an end-of-stream
   *         was encountered.
   * @throws IOException
   *           in case of stream I/O problems;
   */
  public int readLongWord() throws IOException
  {
    final byte[] data = readBytes( 4 );
    if ( data == null )
    {
      return -1;
    }

    return ( int )ByteOrderUtils.decode( getByteOrder(), data );
  }

  /**
   * Reads a word (2 bytes) from the underlying stream.
   *
   * @return the next word, can be <code>-1</code> in case an end-of-stream was
   *         encountered.
   * @throws IOException
   *           in case of stream I/O problems;
   */
  public int readWord() throws IOException
  {
    final byte[] data = readBytes( 2 );
    if ( data == null )
    {
      return -1;
    }

    return ( int )ByteOrderUtils.decode( ByteOrder.LITTLE_ENDIAN, data );
  }

  /**
   * Returns the byte order in which this data provider reads its data.
   *
   * @return a byte order, never <code>null</code>.
   */
  protected abstract ByteOrder getByteOrder();

  /**
   * Convenience method to read a number of bytes.
   *
   * @param aCount
   *          the number of bytes to read, should be > 0.
   * @return a byte array with the read bytes, can be <code>null</code> in case
   *         an EOF was found.
   * @throws IOException
   *           in case of I/O problems;
   * @throws IllegalArgumentException
   *           in case the given count was <= 0.
   */
  protected final byte[] readBytes( final int aCount ) throws IOException, IllegalArgumentException
  {
    if ( aCount <= 0 )
    {
      throw new IllegalArgumentException( "Count cannot be less or equal to zero!" );
    }

    final byte[] result = new byte[aCount];
    for ( int i = 0; i < aCount; i++ )
    {
      int readByte = readByte();
      if ( readByte == -1 )
      {
        return null;
      }
      result[i] = ( byte )readByte;
    }

    return result;
  }

  protected final char[] readChars( final int aCount ) throws IOException, IllegalArgumentException
  {
    if ( aCount <= 0 )
    {
      throw new IllegalArgumentException( "Invalid count!" );
    }
    final char[] buf = new char[aCount];
    if ( this.reader.read( buf ) != aCount )
    {
      throw new IOException( "Unexpected end of stream!" );
    }
    return buf;
  }

  /**
   * Skips until the end-of-line is found.
   */
  protected final int readSingleByte() throws IOException
  {
    int ch;
    do
    {
      ch = this.reader.read();
    }
    while ( ( ch != -1 ) && Character.isWhitespace( ch ) );
    return ch;
  }

}
