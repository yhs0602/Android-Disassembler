/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2017 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2.
 */
package nl.lxtreme.binutils.hex.util;


public interface Checksummer
{

  /**
   * Adds a given value to the checksum.
   *
   * @param values
   *          the byte values to add to this checksum.
   * @return this checksummer instance, for chaining purposes.
   */
  Checksummer add( byte... values );

  /**
   * Adds a given word (16-bit) value to the checksum.
   * <p>
   * This method is a convenience method for calling: <code><pre>
   *   add((byte)(value >> 8));
   *   add((byte)(value & 0xFF));
   * </pre></code>
   *
   * @param value
   *          the word value to add to this checksum.
   * @return this checksummer instance, for chaining purposes.
   */
  Checksummer addWord( int value );

  /**
   * Returns the resulting checksum of all previously added values.
   *
   * @return the resulting checksum value.
   */
  byte getResult();

  /**
   * Prepares this instance for a new checksum.
   *
   * @return this checksummer instance, for chaining purposes.
   */
  Checksummer reset();

}
