/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2017 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.hex.util;


import java.nio.*;


/**
 * In computing, endianness is the byte (and sometimes bit) ordering used to
 * represent some kind of data. Typical cases are the order in which integer
 * values are stored as bytes in computer memory (relative to a given memory
 * addressing scheme) and the transmission order over a network or other medium.
 * When specifically talking about bytes, endianness is also referred to simply
 * as byte order.
 */
public class ByteOrderUtils
{
  // CONSTRUCTORS

  private ByteOrderUtils()
  {
    // NO-op
  }

  // METHODS

  /**
   * Creates a (16-bit) word value with the correct byte order.
   *
   * @param aMSB
   *          the most significant byte;
   * @param aLSB
   *          the least significant byte.
   * @return the 16-bit combination of both given bytes in the order of
   *         endianness.
   */
  public static int createWord( final ByteOrder aByteOrder, final int aMSB, final int aLSB )
  {
    if ( aByteOrder == ByteOrder.BIG_ENDIAN )
    {
      return ( ( aMSB << 8 ) & 0xFF00 ) | ( aLSB & 0x00FF );
    }

    return ( ( aLSB << 8 ) & 0xFF00 ) | ( aMSB & 0x00FF );
  }

  /**
   * Creates a (16-bit) word value with the correct byte order.
   *
   * @param aMSB
   *          the most significant byte;
   * @param aLSB
   *          the least significant byte.
   * @return the 16-bit combination of both given bytes in the order of
   *         endianness.
   */
  public static int createWord( final int aMSB, final int aLSB )
  {
    return createWord( ByteOrder.nativeOrder(), aMSB, aLSB );
  }

  /**
   * Convenience method to create a single value using the given byte values in
   * a given byte order.
   *
   * @param aExpectedByteOrder
   *          the expected byte order;
   * @param aBytes
   *          the bytes to decode into a single value, their order depends!
   * @return the word in the expected byte order.
   */
  public static long decode( final ByteOrder aExpectedByteOrder, final byte... aBytes )
  {
    final int byteCount = aBytes.length;
    final int lastByteIdx = byteCount - 1;

    long result = 0L;

    if ( aExpectedByteOrder == ByteOrder.BIG_ENDIAN )
    {
      for ( int i = 0; i < byteCount; i++ )
      {
        result <<= 8;
        result |= ( aBytes[i] & 0xFF );
      }
    }
    else if ( aExpectedByteOrder == ByteOrder.LITTLE_ENDIAN )
    {
      for ( int i = lastByteIdx; i >= 0; i-- )
      {
        result <<= 8;
        result |= ( aBytes[i] & 0xFF );
      }
    }

    return result;
  }

  /**
   * Switches the order of bytes of the given (16-bit) word value.
   * <p>
   * In effect, this method casts a little-endian value to a big-endian value
   * and the other way around.
   * </p>
   *
   * @param aValue
   *          the (16-bit) word value to switch the byte order for.
   * @return the given value with the MSB & LSB switched.
   */
  public static int swap16( final int aValue )
  {
    return ( ( ( aValue & 0x00ff ) << 8 ) | ( ( aValue & 0xff00 ) >> 8 ) );
  }

  /**
   * Switches the order of bytes of the given (32-bit) long word value.
   * <p>
   * In effect, this method casts a little-endian value to a big-endian value
   * and the other way around.
   * </p>
   *
   * @param aValue
   *          the (32-bit) long word value to switch the byte order for.
   * @return the given value with the MSB & LSB switched.
   */
  public static int swap32( final int aValue )
  {
    return ( ( aValue & 0x000000FF ) << 24 ) | ( ( aValue & 0x0000FF00 ) << 8 ) //
        | ( ( aValue & 0xFF000000 ) >>> 24 ) | ( ( aValue & 0x00FF0000 ) >>> 8 );
  }

}
