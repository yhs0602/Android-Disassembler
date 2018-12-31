package com.kyhsgeekcode.disassembler;

//represents a raw file and interface
import java.io.*;
import java.nio.channels.*;
import java.util.*;
import nl.lxtreme.binutils.elf.*;

public abstract class AbstractFile implements Closeable
{
	public void setPath(String path)
	{
		this.path = path;
	}

	public String getPath()
	{
		return path;
	}
	public MachineType getMachineType()
	{
		return machineType;
	}
	@Override
	public void close() throws IOException
	{
		return ;
	}
	public long getEntryPoint()
	{
		return entryPoint;
	}
	public long getCodeSectionBase()
	{
		return codeBase;
	}
	public long getCodeSectionLimit()
	{
		return codeLimit;
	}
	public long getCodeVirtAddr()
	{
		return codeVirtualAddress;
	}
	public List<Symbol> getExportSymbols()
	{
		if(exportSymbols==null)
			exportSymbols=new ArrayList<>();
		return exportSymbols;
	}

	public List<PLT> getImportSymbols()
	{
		if(importSymbols==null)
			importSymbols=new ArrayList<>();
		return importSymbols;
	}
	@Override
	public String toString()
	{	
		StringBuilder builder=new StringBuilder("");
		builder.append("File size: ").append(Integer.toHexString(fileContents.length))
		.append(ls);
		builder.append("File offset of CS: ").append(Long.toHexString(codeBase))
		.append(ls);
		builder.append("File offset of CS end :").append(Long.toHexString(codeLimit))
		.append(ls);
		builder.append("File offset of entry point: ").append(Long.toHexString(codeBase+entryPoint))
		.append(ls);
		builder.append("Virtual address of CS: ").append(Long.toHexString(codeVirtualAddress))
		.append(ls);
		builder.append("Virtual address of CS end: ").append(Long.toHexString(codeLimit+codeVirtualAddress))
		.append(ls);
		builder.append("Virtual address of EP: ").append(Long.toHexString(entryPoint+codeVirtualAddress));
		return builder.toString();
	}
//	public AbstractFile(File file) throws IOException
//	{
//		
//	}
//	public AbstractFile(FileChannel channel)
//	{
//		
//	}
	String ls=System.lineSeparator();
	long codeBase=0;
	long codeLimit=0;
	List<Symbol> exportSymbols;
	List<PLT> importSymbols;
	byte[] fileContents;
	long entryPoint=0;
	long codeVirtualAddress=0;
	MachineType machineType;
	String path="";
}
