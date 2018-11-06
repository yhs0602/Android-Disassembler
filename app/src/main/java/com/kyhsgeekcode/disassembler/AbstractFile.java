package com.kyhsgeekcode.disassembler;

//represents a raw file and interface
import java.io.*;
import java.nio.channels.*;
import java.util.*;
import nl.lxtreme.binutils.elf.*;

public abstract class AbstractFile implements Closeable
{
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
	public List<Symbol> getSymbols()
	{
		if(symbols==null)
			symbols=new ArrayList<>();
		return symbols;
	}
//	public AbstractFile(File file) throws IOException
//	{
//		
//	}
//	public AbstractFile(FileChannel channel)
//	{
//		
//	}
	long codeBase=0;
	long codeLimit=0;
	List<Symbol> symbols;
	byte[] fileContents;
	long entryPoint=0;
	long codeVirtualAddress=0;
	MachineType machineType;
}
