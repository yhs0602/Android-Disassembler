/*******************************************************************************
 * Copyright (c) 2011 - J.W. Janssen
 * 
 * Copyright (c) 2000, 2008 QNX Software Systems and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     QNX Software Systems - Initial API and implementation
 *     Abeer Bagul (Tensilica) - bug 102434
 *     Anton Leherbauer (Wind River Systems)
 *     J.W. Janssen - Cleanup and some small API changes.
 *******************************************************************************/
package nl.lxtreme.binutils.ar;


import java.io.*;
import java.util.*;


/**
 * Used for parsing standard ELF archive (ar) files. Each object within the
 * archive is represented by an ARHeader class. Each of of these objects can
 * then be turned into an Elf object for performing Elf class operations.
 * 
 * @see AREntry
 */
public class AR
{
  // VARIABLES

  private final String path;
  private RandomAccessFile efile;
  private long stringTableOffset;
  private Collection<AREntry> headers;

  // CONSTRUCTORS

  /**
   * Creates a new <code>AR</code> object from the contents of the given file.
   * 
   * @param aFile
   *          The AR archive file to process.
   * @throws IllegalArgumentException
   *           in case the given file was <code>null</code>;
   * @throws IOException
   *           if the given file is not a valid AR archive.
   */
  public AR( final File aFile ) throws IOException
  {
    if ( aFile == null )
    {
      throw new IllegalArgumentException( "Parameter File cannot be null!" );
    }

    this.path = aFile.getAbsolutePath();
    this.efile = new RandomAccessFile( aFile, "r" );

    final byte[] hdrBytes = new byte[7];
    this.efile.readFully( hdrBytes );

    if ( !AREntry.isARHeader( hdrBytes ) )
    {
      this.efile.close();
      this.efile = null;

      throw new IOException( "Invalid AR archive! No header found." );
    }

    this.efile.readLine();
  }

  // METHODS

  /**
   * Disposes all resources for this AR archive.
   */
  public void dispose()
  {
    try
    {
      if ( this.efile != null )
      {
        this.efile.close();
        this.efile = null;
      }
    }
    catch ( final IOException exception )
    {
      // Ignored...
    }
  }

  /**
   * Extracts all files from this archive matching the given names.
   * 
   * @param aOutputDir
   *          the output directory to extract the files to, cannot be
   *          <code>null</code>;
   * @param aNames
   *          the names of the files to extract, if omitted all files will be
   *          extracted.
   * @throws IllegalArgumentException
   *           in case the given output directory was <code>null</code>;
   * @throws IOException
   *           in case of I/O problems.
   */
  public void extractFiles( final File aOutputDir, final String... aNames ) throws IOException
  {
    if ( aOutputDir == null )
    {
      throw new IllegalArgumentException( "Parameter OutputDir cannot be null!" );
    }

    for ( final AREntry header : getEntries() )
    {
      String fileName = header.getFileName();
      if ( ( aNames != null ) && !stringInStrings( aNames, fileName ) )
      {
        continue;
      }

      this.efile.seek( header.getFileOffset() );

      extractFile( header, new File( aOutputDir, fileName ) );
    }
  }

  /**
   * Returns the name of this archive.
   * 
   * @return an archive name, never <code>null</code>.
   */
  public String getArchiveName()
  {
    return this.path;
  }

  /**
   * Get an array of all the object file headers for this archive.
   * 
   * @throws IOException
   *           Unable to process the archive file.
   * @return An array of headers, one for each object within the archive.
   * @see AREntry
   */
  public Collection<AREntry> getEntries() throws IOException
  {
    if ( this.headers == null )
    {
      this.headers = loadEntries();
    }
    return Collections.unmodifiableCollection( this.headers );
  }

  /**
   * Returns all names of the entries in this archive.
   * 
   * @return a collection of entry names, never <code>null</code>.
   * @throws IOException
   *           in case of I/O problems.
   */
  public Collection<String> getEntryNames() throws IOException
  {
    Collection<AREntry> entries = getEntries();

    List<String> result = new ArrayList<String>( entries.size() );
    for ( AREntry entry : entries )
    {
      result.add( entry.getFileName() );
    }

    return Collections.unmodifiableCollection( result );
  }

  /**
   * Reads a file and writes the results to the given writer object.
   * 
   * @param aWriter
   *          the writer to write the file contents to, cannot be
   *          <code>null</code>;
   * @param aName
   *          the name of the file to read, cannot be <code>null</code>.
   * @return <code>true</code> if the file was successfully read,
   *         <code>false</code> otherwise.
   * @throws IllegalArgumentException
   *           in case either one of the given arguments was <code>null</code>;
   * @throws IOException
   *           in case of I/O problems.
   */
  public boolean readFile( final Writer aWriter, final String aName ) throws IOException
  {
    if ( aWriter == null )
    {
      throw new IllegalArgumentException( "Parameter Writer cannot be null!" );
    }
    if ( aName == null )
    {
      throw new IllegalArgumentException( "Parameter Name cannot be null!" );
    }

    for ( final AREntry header : getEntries() )
    {
      String name = header.getFileName();
      if ( aName.equals( name ) )
      {
        this.efile.seek( header.getFileOffset() );

        extractFile( header, aWriter );
        return true;
      }
    }

    return false;
  }

  /**
   * Look up the name stored in the archive's string table based on the offset
   * given. Maintains <code>efile</code> file location.
   * 
   * @param aOffset
   *          Offset into the string table for first character of the name.
   * @throws IOException
   *           <code>offset</code> not in string table bounds.
   */
  final String nameFromStringTable( final long aOffset ) throws IOException
  {
    if ( this.stringTableOffset < 0 )
    {
      throw new IOException( "Invalid AR archive! No string table read yet?!" );
    }

    final StringBuilder name = new StringBuilder();

    final long originalPos = this.efile.getFilePointer();

    try
    {
      this.efile.seek( this.stringTableOffset + aOffset );

      byte temp;
      while ( ( temp = this.efile.readByte() ) != '\n' )
      {
        name.append( ( char )temp );
      }
    }
    finally
    {
      this.efile.seek( originalPos );
    }

    return name.toString();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void finalize() throws Throwable
  {
    try
    {
      dispose();
    }
    finally
    {
      super.finalize();
    }
  }

  /**
   * Extracts the given entry and writes its data to a given file.
   * 
   * @param aEntry
   *          the entry to extract;
   * @param aFile
   *          the file to write the entry data to.
   * @throws IOException
   *           in case of I/O problems.
   */
  private void extractFile( final AREntry aEntry, final File aFile ) throws IOException
  {
    final FileWriter fw = new FileWriter( aFile );

    try
    {
      extractFile( aEntry, fw );
    }
    finally
    {
      try
      {
        fw.close();
      }
      catch ( final IOException exception )
      {
        // Ignore...
      }
    }
  }

  /**
   * Extracts the given entry and writes its data to a given file.
   * 
   * @param aEntry
   *          the entry to extract;
   * @param aWriter
   *          the {@link Writer} to write the entry data to.
   * @throws IOException
   *           in case of I/O problems.
   */
  private void extractFile( final AREntry aEntry, final Writer aWriter ) throws IOException
  {
    try
    {
      long bytesToRead = aEntry.getSize();

      while ( bytesToRead > 0 )
      {
        final int byteRead = this.efile.read();
        if ( ( byteRead < 0 ) && ( bytesToRead != 0 ) )
        {
          throw new IOException( "Invalid AR archive! Premature end of archive?!" );
        }

        aWriter.write( byteRead );
        bytesToRead--;
      }
    }
    finally
    {
      try
      {
        aWriter.flush();
      }
      catch ( final IOException exception )
      {
        // Ignore...
      }
    }
  }

  /**
   * Load the entries from the archive (if required).
   * 
   * @return the read entries, never <code>null</code>.
   */
  private Collection<AREntry> loadEntries() throws IOException
  {
    final List<AREntry> headers = new ArrayList<AREntry>();

    // Check for EOF condition
    while ( this.efile.getFilePointer() < this.efile.length() )
    {
      final AREntry header = AREntry.create( this, this.efile );

      if ( !header.isSpecial() )
      {
        headers.add( header );
      }

      long pos = this.efile.getFilePointer();
      if ( header.isStringTableSection() )
      {
        this.stringTableOffset = pos;
      }

      // Compute the location of the next header in the archive.
      pos += header.getSize();
      if ( ( pos % 2 ) != 0 )
      {
        pos++;
      }

      this.efile.seek( pos );
    }

    return headers;
  }

  /**
   * Searches for a given subject string in a given set of strings.
   * 
   * @param aSet
   *          the set of strings to search;
   * @param aSubject
   *          the subject to search for.
   * @return <code>true</code> if the given subject was found in the given set,
   *         <code>false</code> otherwise.
   */
  private boolean stringInStrings( final String[] aSet, final String aSubject )
  {
    for ( final String element : aSet )
    {
      if ( aSubject.equals( element ) )
      {
        return true;
      }
    }
    return false;
  }
}
