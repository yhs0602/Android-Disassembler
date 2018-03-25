package com.jourhyang.disasmarm;
import java.io.*;
//import org.apache.http.*;
import nl.lxtreme.binutils.*;
import nl.lxtreme.binutils.elf.*;
public class ELFUtil
{
	Elf elf;
	public long getEntryPoint()
	{
		return entryPoint;
	}
	public String toString()
	{
		return elf.toString();
	}
	public static int getWord(byte a, byte b, byte c, byte d)
	{
		return ((int)a << 24) & ((int)b << 16) & ((int)c << 8) & d;
	}
	/*
	 public ELFUtil(File file) throws Exception
	 {
	 long fsize=file.length();
	 int index=0;
	 fileContents=new byte[(int)fsize];
	 DataInputStream in = new DataInputStream(new FileInputStream(file.getPath()));
	 int len,counter=0;
	 byte[] b=new byte[1024];
	 while ((len = in.read(b)) > 0)
	 {
	 for (int i = 0; i < len; i++)
	 { // byte[] 버퍼 내용 출력
	 //System.out.format("%02X ", b[i]);
	 fileContents[index] = b[i];
	 index++;
	 counter++;
	 }
	 }

	 ParseData();
	 }
	 public ELFUtil(byte[] bytes) throws Exception
	 {
	 fileContents=new byte[bytes.length];
	 for(int s=0;s<bytes.length;++s)
	 {
	 fileContents[s]=bytes[s];
	 }
	 ParseData();
	 }
	 */
	public ELFUtil(File file) throws IOException
	{
		elf = new Elf(file);
		SectionHeader[] sections = elf.sectionHeaders;
		//assertNotNull( sections );

		ProgramHeader[] programHeaders = elf.programHeaders;
		//assertNotNull( programHeaders );

		//dumpProgramHeaders( programHeaders );

		Header header = elf.header;
		//assertNotNull( header );
		//bExecutable=header.elfType;
		entryPoint = header.entryPoint;
		//CodeBase=
		//System.out.printf( "Entry point: 0x%x\n", header.entryPoint );
	}
	public void ParseData() throws Exception
	{
		if (fileContents == null)
		{
			return;
		}
		if (fileContents.length < 54)
		{
			//return;
			throw new Exception("Not a ELF HEADER");
		}
		entryPoint = getWord((byte)0, (byte)0, (byte)0, (byte)0);
	}
	private long entryPoint;
	private byte [] fileContents;
	boolean bExecutable;
	private long CodeBase;
}
