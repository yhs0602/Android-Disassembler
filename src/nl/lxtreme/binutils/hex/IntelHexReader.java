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
 * Provides a data provider based on a Intel-HEX file.
 * <p>
 * A file in the Intel hex-format is a text file containing hexadecimal encoded
 * data, organised in so-called records: a text line in the following format:
 * </p>
 *
 * <pre>
 *     :&lt;datacount&gt;&lt;address&gt;&lt;recordtype&gt;&lt;data&gt;&lt;checksum&gt;
 * </pre>
 * <p>
 * In which is:
 * </p>
 * <ul>
 * <li><b>':'</b>, the identifying character of the record;</li>
 * <li><b>datacount</b>, the hex-encoded byte representing the number of data
 * bytes in the record;</li>
 * <li><b>address</b>, the hex-encoded 2-byte address;</li>
 * <li><b>recordtype</b>, hex-encoded byte representing the record type:
 * <ul>
 * <li>'00': data record (like the Motorola record type "S1");</li>
 * <li>'01': termination record (like the Motorola record type "S9");</li>
 * <li>'02': segment base address record, the first word of data of this record
 * used as Segment Base Address of the addresses of the next data records;
 * actual addresses are calculated as: start address := (SegmentBaseAddress*16)
 * + record start address;</li>
 * <li>'04': unknown record-type, the first word of data of this record is
 * interpreted by Binex as Segment Address, the most significant word of the
 * addresses of the next data records; actual addresses are calculated as: start
 * address := (SegmentAddress*65536) + record start address;</li>
 * </ul>
 * </li>
 * <li><b>data</b>, the hex-encoded data bytes (maximum 255);</li>
 * <li><b>checksum</b>, the two's complement of the sum of all bytes in the
 * record after the identifying character.</li>
 * </ul>
 * <p>
 * Files with only 00, and 01 records are called to be in Intel "Intellec" 8/MDS
 * format. The Intel MCS86 (Intellec 86) format adds the 02 type records to
 * that.
 * </p>
 */
public class IntelHexReader extends AbstractReader
{
  // CONSTANTS

  private static final char PREAMBLE = ':';

  private static final int DATA_TYPE = 0;
  private static final int TERMINATION_TYPE = 1;
  private static final int EXTENDED_SEGMENT_ADDRESS_TYPE = 2;
  private static final int START_SEGMENT_ADDRESS_TYPE = 3;
  private static final int EXTENDED_LINEAR_ADDRESS_TYPE = 4;
  private static final int START_LINEAR_ADDRESS_TYPE = 5;

  // VARIABLES

  private final Checksummer checksum;

  private Integer segmentBaseAddress;
  private Integer linearAddress;
  private Integer address;
  private Integer dataLength;

  // CONSTRUCTORS

  /**
   * Creates a new IntelHexDataProvider instance.
   *
   * @param aReader
   *          the reader to use.
   */
  public IntelHexReader( final Reader aReader )
  {
    super( aReader );

    this.checksum = Checksum.TWOS_COMPLEMENT.instance();
  }

  // METHODS

  @Override
  public long getAddress() throws IOException
  {
    if ( this.address == null )
    {
      throw new IOException( "Unexpected call to getAddress!" );
    }
    return this.address.longValue();
  }

  @Override
  public int readByte() throws IOException
  {
    int ch;

    do
    {
      ch = readSingleByte();
      if ( ch == -1 )
      {
        // End-of-file reached; return immediately!
        return -1;
      }

      if ( PREAMBLE == ch )
      {
        // New record started...
        startNewDataRecord();
      }
      else if ( this.dataLength != null )
      {
        final int secondHexDigit = this.reader.read();
        if ( secondHexDigit == -1 )
        {
          throw new IOException( "Unexpected end-of-stream!" );
        }

        final char[] buf = { ( char )ch, ( char )secondHexDigit };

        final byte dataByte = HexUtils.parseHexByte( buf );
        if ( this.dataLength == 0 )
        {
          // All data-bytes returned? If so, verify the CRC we've just read...
          final byte calculatedCRC = this.checksum.getResult();
          if ( dataByte != calculatedCRC )
          {
            throw new IOException( "CRC Error! Expected: 0x" + Integer.toHexString( dataByte ) + "; got: 0x"
                + Integer.toHexString( calculatedCRC ) );
          }
        }
        else
        {
          // Decrease the number of hex-bytes we've got to read...
          this.checksum.add( ( byte )dataByte );

          this.dataLength--;
          this.address++;

          return ( dataByte & 0xFF );
        }
      }
    }
    while ( ch != -1 );

    // We should never come here; it means that we've found a situation that
    // isn't covered by our loop above...
    throw new IOException( "Invalid Intel HEX-file!" );
  }

  @Override
  protected ByteOrder getByteOrder()
  {
    return ByteOrder.LITTLE_ENDIAN;
  }

  /**
   * Starts a new data record, calculates the initial address, and checks what
   * kind of data the record contains.
   *
   * @throws IOException
   *           in case of I/O problems.
   */
  private void startNewDataRecord() throws IOException
  {
    // First byte is the length of the data record...
    this.dataLength = ( int )HexUtils.readHexByte( this.reader );

    // When a segment base address is previously set, calculate the actual
    // address by OR-ing this base-address with the address of the record...
    this.address = HexUtils.readHexWord( this.reader );
    if ( ( this.segmentBaseAddress != null ) && ( this.segmentBaseAddress > 0 ) )
    {
      this.address = this.segmentBaseAddress | this.address;
    }
    else if ( ( this.linearAddress != null ) && ( this.linearAddress > 0 ) )
    {
      this.address = ( this.linearAddress << 16 ) | this.address;
    }

    final int recordType = HexUtils.readHexByte( this.reader );

    // Calculate the first part of the record CRC; which is defined as the
    // ones-complement of all (non-CRC) items in the record...
    this.checksum.reset();
    this.checksum.add( this.dataLength.byteValue() );
    this.checksum.add( ( byte )recordType );
    this.checksum.addWord( this.address );

    if ( DATA_TYPE == recordType )
    {
      // Ok, found first data item... Adjust address with a single byte in
      // order to obtain a valid first address...
      this.address--;
    }
    else if ( EXTENDED_SEGMENT_ADDRESS_TYPE == recordType )
    {
      this.segmentBaseAddress = HexUtils.readHexWord( this.reader );

      this.checksum.addWord( this.segmentBaseAddress );

      // Ignore the rest of the data; but calculate the CRC...
      this.dataLength = 0;
    }
    else if ( EXTENDED_LINEAR_ADDRESS_TYPE == recordType )
    {
      this.linearAddress = HexUtils.readHexWord( this.reader );

      this.checksum.addWord( this.linearAddress );

      // Ignore the rest of the data; but calculate the CRC...
      this.dataLength = 0;
    }
    else if ( TERMINATION_TYPE == recordType )
    {
      // Ignore the rest of the data; but calculate the CRC...
      this.dataLength = 0;
    }
    else if ( ( START_LINEAR_ADDRESS_TYPE != recordType ) && ( START_SEGMENT_ADDRESS_TYPE != recordType ) )
    {
      throw new IOException( "Unknown Intel record type: " + recordType );
    }
  }
}
