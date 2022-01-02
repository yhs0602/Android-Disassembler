/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2017 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.hex.util;


import java.io.*;


/**
 * Provides some convenience utilities to work with strings of hex digits.
 */
public final class HexUtils
{
  // CONSTRUCTORS

  /**
   * Creates a new HexUtils instance.
   */
  private HexUtils()
  {
    // NO-op
  }

  // METHODS

  /**
   * Parses the hex-byte in the given character sequence at the given offset.
   *
   * @param aInput
   *          the characters to parse as hex-bytes.
   * @return a byte value.
   * @throws IllegalArgumentException
   *           in case the given char sequence was <code>null</code>, in case
   *           the given input did not yield a hex-byte, or the requested offset
   *           is outside the boundaries of the given char sequence.
   */
  public static byte parseHexByte( char[] aInput ) throws IllegalArgumentException
  {
    if ( aInput == null )
    {
      throw new IllegalArgumentException( "Input cannot be null!" );
    }
    if ( aInput.length < 2 )
    {
      throw new IllegalArgumentException( "Input should be at least two characters!" );
    }
    return ( byte )( ( parseHex( aInput[0] ) << 4 ) | ( parseHex( aInput[1] ) ) );
  }

  /**
   * Reads two characters from the given reader and parses them as a single
   * hex-value byte.
   *
   * @param aReader
   * @return
   * @throws IllegalArgumentException
   * @throws IOException
   */
  public static byte readHexByte( Reader aReader ) throws IllegalArgumentException, IOException
  {
    return ( byte )readHexNumber( aReader, 1 );
  }

  /**
   * Reads a number of characters from the given reader and parses them as a
   * hex-value.
   *
   * @param aReader
   *          the reader to read the data from;
   * @param aByteCount
   *          the number of bytes to read (= 2 * amount of actual characters
   *          read).
   * @return the parsed number.
   * @throws IllegalArgumentException
   *           in case the given reader was <code>null</code> or the given byte
   *           count was <= 0.
   * @throws IOException
   *           in case of I/O problems.
   */
  public static int readHexNumber( Reader aReader, int aByteCount ) throws IllegalArgumentException, IOException
  {
    if ( aReader == null )
    {
      throw new IllegalArgumentException( "Input cannot be null!" );
    }
    if ( aByteCount <= 0 )
    {
      throw new IllegalArgumentException( "Byte count cannot be less or equal to zero!" );
    }

    int result = 0;
    int nibbleCount = 2 * aByteCount;
    while ( nibbleCount-- > 0 )
    {
      int hexdigit = parseHex( aReader.read() );
      result = ( result << 4 ) | hexdigit;
    }

    return result;
  }

  /**
   * Reads four characters from the given reader and parses them as a single
   * hex-value word.
   *
   * @param aReader
   * @return
   * @throws IllegalArgumentException
   * @throws IOException
   */
  public static int readHexWord( Reader aReader ) throws IllegalArgumentException, IOException
  {
    return ( readHexNumber( aReader, 2 ) & 0xFFFF );
  }

  private static int parseHex( int c )
  {
    int v = Character.digit( c, 16 );
    if ( v < 0 )
    {
      throw new IllegalArgumentException( "Unexpected character: " + c );
    }
    return v;
  }
}
