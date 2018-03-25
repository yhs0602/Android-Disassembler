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


/**
 * The <code>ARHeader</code> class is used to store the per-object file
 * archive headers. It can also create an Elf object for inspecting
 * the object file data.
 */
public class AREntry
{
  // CONSTANTS

  private static final int NAME_IDX = 0;
  private static final int NAME_LEN = 16;
  private static final int MTIME_IDX = 16;
  private static final int MTIME_LEN = 12;
  private static final int UID_IDX = 28;
  private static final int UID_LEN = 6;
  private static final int GID_IDX = 34;
  private static final int GID_LEN = 6;
  private static final int MODE_IDX = 40;
  private static final int MODE_LEN = 8;
  private static final int SIZE_IDX = 48;
  private static final int SIZE_LEN = 10;
  private static final int MAGIC_IDX = 58;
  @SuppressWarnings("unused")
  private static final int MAGIC_LEN = 2;
  private static final int HEADER_LEN = 60;

  // VARIABLES

  private String fileName;
  private long fileOffset;
  private long modificationTime;
  private int uid;
  private int gid;
  private int mode;
  private long size;

  // CONSTRUCTORS

  /**
   * Creates a new archive header object.
   */
  private AREntry()
  {
    super();
  }

  // METHODS

  /**
   * Factory method to create a {@link AREntry} for the given {@link AR}
   * archive.
   * 
   * @param aArchive
   *          the archive to read the header for;
   * @param aFile
   *          the file of the archive to read the header from.
   * @return the newly read header, never <code>null</code>.
   * @throws IOException
   *           in case of I/O problems.
   */
  static AREntry create(final AR aArchive, final RandomAccessFile aFile) throws IOException
  {
    final AREntry result = new AREntry();

    byte[] buf = new byte[HEADER_LEN];

    // Read in the archive header data. Fixed sizes.
    aFile.readFully(buf);

    // Save this location so we can create the Elf object later.
    result.fileOffset = aFile.getFilePointer();

    // Convert the raw bytes into strings and numbers.
    result.fileName = new String(buf, NAME_IDX, NAME_LEN).trim();
    result.size = Long.parseLong(new String(buf, SIZE_IDX, SIZE_LEN).trim());

    if (!result.isSpecial())
    {
      result.modificationTime = Long.parseLong(new String(buf, MTIME_IDX, MTIME_LEN).trim());
      result.uid = Integer.parseInt(new String(buf, UID_IDX, UID_LEN).trim());
      result.gid = Integer.parseInt(new String(buf, GID_IDX, GID_LEN).trim());
      result.mode = Integer.parseInt(new String(buf, MODE_IDX, MODE_LEN).trim(), 8);

      if ((buf[MAGIC_IDX] != 0x60) && (buf[MAGIC_IDX + 1] != 0x0A))
      {
        throw new IOException("Not a valid AR archive! No file header magic found.");
      }
    }

    // If the name is something like "#1/<num>", then we're dealing with a BSD
    // ar file. The <num> is the actual file name length, and the file name
    // itself is available directly after the header...
    if (result.isBSDArExtendedFileName())
    {
      try
      {
        final int fileNameLength = Integer.parseInt(result.fileName.substring(3));
        if (fileNameLength > 0)
        {
          buf = new byte[fileNameLength];
          aFile.readFully(buf);

          result.fileName = new String(buf).trim();
        }
      }
      catch (final NumberFormatException exception)
      {
        throw new IOException("Invalid AR archive! (BSD) Extended filename invalid?!");
      }
    }

    // If the name is of the format "/<number>", we're dealing with a GNU ar
    // file and we should get name from the string table...
    if (result.isGNUArExtendedFileName())
    {
      try
      {
        final long offset = Long.parseLong(result.fileName.substring(1));
        result.fileName = aArchive.nameFromStringTable(offset);
      }
      catch (final NumberFormatException exception)
      {
        throw new IOException("Invalid AR archive! (GNU) Extended filename invalid?!");
      }
    }

    // Strip the trailing / from the object name.
    final int len = result.fileName.length();
    if ((len > 2) && (result.fileName.charAt(len - 1) == '/'))
    {
      result.fileName = result.fileName.substring(0, len - 1);
    }

    return result;
  }

  /**
   * Determines whether the given byte array contains the global AR header,
   * consisting of the string "!<arch>".
   * 
   * @param aIdent
   *          the byte array with the possible AR header.
   * @return <code>true</code> if the given byte array contains the AR header,
   *         <code>false</code> otherwise.
   */
  static boolean isARHeader(final byte[] aIdent)
  {
    if ((aIdent.length < 7)
          || (aIdent[0] != '!')
          || (aIdent[1] != '<')
          || (aIdent[2] != 'a')
          || (aIdent[3] != 'r')
          || (aIdent[4] != 'c')
          || (aIdent[5] != 'h')
          || (aIdent[6] != '>'))
    {
      return false;
    }
    return true;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object aObject)
  {
    if (this == aObject)
    {
      return true;
    }
    if ((aObject == null) || (getClass() != aObject.getClass()))
    {
      return false;
    }

    final AREntry other = (AREntry) aObject;
    if (this.fileName == null)
    {
      if (other.fileName != null)
      {
        return false;
      }
    }
    else if (!this.fileName.equals(other.fileName))
    {
      return false;
    }
    if (this.fileOffset != other.fileOffset)
    {
      return false;
    }
    if (this.gid != other.gid)
    {
      return false;
    }
    if (this.mode != other.mode)
    {
      return false;
    }
    if (this.modificationTime != other.modificationTime)
    {
      return false;
    }
    if (this.size != other.size)
    {
      return false;
    }
    if (this.uid != other.uid)
    {
      return false;
    }
    return true;
  }

  /**
   * Returns UNIX file mode, containing the permissions of the file.
   * 
   * @return the mode, should be interpreted as octal value.
   */
  public int getFileMode()
  {
    return this.mode;
  }

  /**
   * Get the name of the object file
   */
  public String getFileName()
  {
    return this.fileName;
  }

  /**
   * Returns the group ID of the file.
   * 
   * @return the group ID, as integer value, >= 0.
   */
  public int getGID()
  {
    return this.gid;
  }

  /**
   * Returns the timestamp of the file.
   * 
   * @return the timestamp, as epoch time.
   */
  public long getModificationTime()
  {
    return this.modificationTime;
  }

  /**
   * Get the size of the object file .
   */
  public long getSize()
  {
    return this.size;
  }

  /**
   * Returns the user ID of the file.
   * 
   * @return the user ID, as integer value, >= 0.
   */
  public int getUID()
  {
    return this.uid;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int hashCode()
  {
    final int prime = 31;
    int result = 1;
    result = prime * result + (int) (this.modificationTime ^ (this.modificationTime >>> 32));
    result = prime * result + ((this.fileName == null) ? 0 : this.fileName.hashCode());
    result = prime * result + (int) (this.fileOffset ^ (this.fileOffset >>> 32));
    result = prime * result + (int) (this.size ^ (this.size >>> 32));
    result = prime * result + this.gid;
    result = prime * result + this.mode;
    result = prime * result + this.uid;
    return result;
  }

  /**
   * Returns whether this header represents a special file.
   * 
   * @return <code>true</code> if this header represents a special file,
   *         <code>false</code> otherwise.
   */
  public boolean isSpecial()
  {
    return this.fileName.charAt(0) == '/';
  }

  /**
   * Returns whether this header represents the string table section.
   * 
   * @return <code>true</code> if this header represents a string table section,
   *         <code>false</code> otherwise.
   */
  public boolean isStringTableSection()
  {
    return this.fileName.equals("//");
  }

  /**
   * Returns the file offset in the complete binary.
   * 
   * @return a file offset (in bytes), >= 0.
   */
  final long getFileOffset()
  {
    return this.fileOffset;
  }

  /**
   * Returns whether this header is created by BSD ar, and represents an
   * extended filename.
   * 
   * @return <code>true</code> if this header is an extended filename created by
   *         BSD ar, <code>false</code> otherwise.
   */
  final boolean isBSDArExtendedFileName()
  {
    return this.fileName.matches("^#1/\\d+$");
  }

  /**
   * Returns whether this header is created by GNU ar, and represents an
   * extended filename.
   * 
   * @return <code>true</code> if this header is an extended filename created by
   *         GNU ar, <code>false</code> otherwise.
   */
  final boolean isGNUArExtendedFileName()
  {
    return this.fileName.matches("^/\\d+$");
  }
}
