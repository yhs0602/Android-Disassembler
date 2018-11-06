package com.kyhsgeekcode.disassembler;

import android.util.*;
import java.io.*;
import java.nio.*;
import java.util.*;
import nl.lxtreme.binutils.elf.*;
public class ELFUtil extends AbstractFile
{
	private String TAG="Disassembler elfutil";
	//ArrayList<Symbol> syms;
//	public long getCodeVirtAddr()
//	{
//		return codeVirtualAddress;
//	}
//	public long getCodeSectionLimit()
//	{
//		// TODO: Implement this method
//		return codeLimit;
//	}
	@Override
	public void close() throws IOException
	{
		// TODO: Implement this method
		elf.close();
	}

	Elf elf;
//	public long getEntryPoint()
//	{
//		return entryPoint;
//	}
	@Override
	public String toString()
	{
		return new StringBuilder(elf.toString())
			//.append(Arrays.toString(symstrings))
			.append("\n").append(info).toString();
	}
//	public static int getWord(byte a, byte b, byte c, byte d)
//	{
//		return ((int)a << 24) & ((int)b << 16) & ((int)c << 8) & d;
//	}
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
	@Override
	public long getCodeSectionBase()
	{
		if (codeBase != 0)
		{
			return codeBase;
		}
		Log.e(TAG,"Code base 0?");
		//Do some error
		return 0L;
	}
	/*
	public ELFUtil(FileChannel channel, byte[] filec) throws IOException
	{
		super(null);
		elf = new Elf(channel);
		fileContents = filec;
		AfterConstructor();
	}*/
	public ELFUtil(File file, byte[] filec) throws IOException
	{
		elf = new Elf(file);
		fileContents = filec;
		AfterConstructor();
	}
	public void AfterConstructor() throws IOException
	{
		SectionHeader[] sections = elf.sectionHeaders;
		//assertNotNull( sections );

		ProgramHeader[] programHeaders = elf.programHeaders;
		//assertNotNull( programHeaders );

		//dumpProgramHeaders( programHeaders );
		machineType=elf.header.machineType;
		Header header = elf.header;
		//assertNotNull( header );
		//bExecutable=header.elfType;
		if (header.entryPoint == 0)
		{
			//Log.i(TAG, "file " + file.getName() + "doesnt have entry point. currently set to 0x30");
			entryPoint = 0;
		}
		else
		{
			entryPoint = header.entryPoint;
		}
		if (elf.dynamicTable != null)
		{ 
			StringBuilder sb=new StringBuilder();
			Log.v(TAG, "size of dynamic table=" + elf.dynamicTable.length);
			long strtab=0L;	//pointer to the string table
			long hash=0L;
			int sym_cnt=0;
			int i=0;
			ByteBuffer dynsymbuffer=ByteBuffer.wrap(new byte[]{});
			ByteBuffer symbuffer=ByteBuffer.wrap(new byte[]{});	
			byte[] strtable=elf.getDynamicStringTable();
			ArrayList<Symbol> dynsyms=new ArrayList<>();
			//byte[] symtabs=elf.getDynamicSymbolTable();
			//Syms has DynSyms
			try
			{
				dynsymbuffer=elf.getSection(elf.getSectionHeaderByType(SectionType.DYNSYM));
				ElfClass elfClass=elf.header.elfClass;
				
				if(elfClass.equals(ElfClass.CLASS_32))
				{
					while (dynsymbuffer.hasRemaining())
					{
						int name=dynsymbuffer.getInt();
						int value=dynsymbuffer.getInt();
						int size=dynsymbuffer.getInt();
						short stinfo=dynsymbuffer.get();
						short stother=dynsymbuffer.get();
						short stshndx=dynsymbuffer.getShort();
						String sym_name=Elf.getZString(strtable, name);
						Symbol symbol=new Symbol();
						symbol.name=sym_name;
						symbol.is64=false;
						symbol.st_info=stinfo;
						symbol.st_name=name;
						symbol.st_other=stother;
						symbol.st_shndx=stshndx;
						symbol.st_size=size;
						symbol.st_value=value;
						symbol.analyze();
						dynsyms.add(symbol);
						/*sb.append(sym_name).append("=").append(Integer.toHexString(value))
							.append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
							*/
						sb.append(symbol.toString()).append(System.lineSeparator());
					}		
				}else{// 64
					while (dynsymbuffer.hasRemaining())
					{
						int name=dynsymbuffer.getInt();
						short stinfo=dynsymbuffer.get();
						short stother=dynsymbuffer.get();
						short stshndx=dynsymbuffer.getShort();
						long value=dynsymbuffer.getLong();
						long size=dynsymbuffer.getLong();	
						String sym_name=Elf.getZString(strtable, name);
						Symbol symbol=new Symbol();
						symbol.name=sym_name;
						symbol.is64=true;
						symbol.st_info=stinfo;
						symbol.st_name=name;
						symbol.st_other=stother;
						symbol.st_shndx=stshndx;
						symbol.st_size=size;
						symbol.st_value=value;
						symbol.analyze();
						dynsyms.add(symbol);
						/*sb.append(sym_name).append("=").append(Integer.toHexString(value))
							.append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
							*/
						sb.append(symbol.toString()).append(System.lineSeparator());
					}		
				}
			}
			catch(IllegalArgumentException |IOException e)
			{
				Log.e(TAG,"",e);
			}
			sb.append(System.lineSeparator()).append("syms;").append(System.lineSeparator());
			try
			{
				symbuffer=elf.getSection(elf.getSectionHeaderByType(SectionType.SYMTAB));
				ElfClass elfClass=elf.header.elfClass;
				symbols=new ArrayList<>();
				if(elfClass.equals(ElfClass.CLASS_32))
				{
					while (symbuffer.hasRemaining())
					{
						int name=symbuffer.getInt();
						int value=symbuffer.getInt();
						int size=symbuffer.getInt();
						short stinfo=symbuffer.get();
						short stother=symbuffer.get();
						short stshndx=symbuffer.getShort();
						String sym_name=Elf.getZString(strtable, name);
						Symbol symbol=new Symbol();
						symbol.name=sym_name;
						symbol.is64=false;
						symbol.st_info=stinfo;
						symbol.st_name=name;
						symbol.st_other=stother;
						symbol.st_shndx=stshndx;
						symbol.st_size=size;
						symbol.st_value=value;
						symbol.analyze();
						symbols.add(symbol);
						/*sb.append(sym_name).append("=").append(Integer.toHexString(value))
							.append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
							*/
							sb.append(symbol.toString()).append(System.lineSeparator());
					}		
				}else{// 64
					while (symbuffer.hasRemaining())
					{
						int name=symbuffer.getInt();
						short stinfo=symbuffer.get();
						short stother=symbuffer.get();
						short stshndx=symbuffer.getShort();
						long value=symbuffer.getLong();
						long size=symbuffer.getLong();	
						String sym_name=Elf.getZString(strtable, name);
						Symbol symbol=new Symbol();
						symbol.name=sym_name;
						symbol.is64=true;
						symbol.st_info=stinfo;
						symbol.st_name=name;
						symbol.st_other=stother;
						symbol.st_shndx=stshndx;
						symbol.st_size=size;
						symbol.st_value=value;
						symbol.analyze();
						symbols.add(symbol);
					/*	sb.append(sym_name).append("=").append(Integer.toHexString(value))
							.append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
							*/
							sb.append(symbol.toString()).append(System.lineSeparator());
					}				
				}
			}catch(IllegalArgumentException |IOException|StringIndexOutOfBoundsException e)
			{
				Log.e(TAG,"",e);
			}
			if(symbols==null)
				symbols=new ArrayList<>();
			if(dynsyms!=null)
				symbols.addAll(dynsyms);//I hope this statement be no longer needed in the future, as they may contain duplicates

			/*https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblj/index.html#chapter6-35166
			 Symbol Values
			 Symbol table entries for different object file types have slightly different interpretations for the st_value member.

			 In relocatable files, st_value holds alignment constraints for a symbol whose section index is SHN_COMMON.

			 In relocatable files, st_value holds a section offset for a defined symbol. st_value is an offset from the beginning of the section that st_shndx identifies.

			 In executable and shared object files, st_value holds a virtual address. To make these files' symbols more useful for the runtime linker, the section offset (file interpretation) gives way to a virtual address (memory interpretation) for which the section number is irrelevant.

			 Although the symbol table values have similar meanings for different object files, the data allow efficient access by the appropriate programs.
			 */
			/*https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h
			 /* 32-bit ELF base types. 
			 typedef __u32	Elf32_Addr;
			 typedef __u16	Elf32_Half;
			 typedef __u32	Elf32_Off;
			 typedef __s32	Elf32_Sword;
			 typedef __u32	Elf32_Word;

			 /* 64-bit ELF base types. 
			 typedef __u64	Elf64_Addr;
			 typedef __u16	Elf64_Half;
			 typedef __s16	Elf64_SHalf;
			 typedef __u64	Elf64_Off;
			 typedef __s32	Elf64_Sword;
			 typedef __u32	Elf64_Word;
			 typedef __u64	Elf64_Xword;
			 typedef __s64	Elf64_Sxword;

			 */
			/*https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-79797/index.html
			 typedef struct {
			 Elf32_Word      st_name;
			 Elf32_Addr      st_value;
			 Elf32_Word      st_size;
			 unsigned char   st_info;
			 unsigned char   st_other;
			 Elf32_Half      st_shndx;
			 } Elf32_Sym; size 16

			 typedef struct {
			 Elf64_Word      st_name;
			 unsigned char   st_info;
			 unsigned char   st_other;
			 Elf64_Half      st_shndx;
			 Elf64_Addr      st_value;
			 Elf64_Xword     st_size;
			 } Elf64_Sym; size 24
			 The elements of this structure are:

			 st_name
			 An index into the object file's symbol string table, which holds the character representations of the symbol names.
			 If the value is nonzero, it represents a string table index that gives the symbol name.
			 Otherwise, the symbol table entry has no name.

			 st_value
			 The value of the associated symbol. Depending on the context, this can be an absolute value, an address, and so forth. See "Symbol Values".

			 st_size
			 Many symbols have associated sizes. For example, a data object's size is the number of bytes contained in the object. This member holds 0 if the symbol has no size or an unknown size.

			 */
			info = sb.toString();
			//Log.i(TAG, "info=" + info);
		}
		Log.v(TAG, "Checking code section");
		for (SectionHeader sh:elf.sectionHeaders)
		{
			Log.v(TAG, "type=" + sh.type.toString() + "name=" + sh.getName());
			if (sh.type.equals(SectionType.PROGBITS))
			{
				Log.v(TAG, "sh.type.equals Progbits");
				String name=sh.getName();
				if (name != null)
				{
					Log.i(TAG, "name nonnull:name=" + name);
					if (name.equals(".text"))
					{
						codeBase = sh.fileOffset;
						codeLimit = codeBase + sh.size;
						codeVirtualAddress = sh.virtualAddress;
					}
				}
			}
		}
	}
	
	String info="";
	/*
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
	}*/
	//private long entryPoint;
	//private byte [] fileContents;
	boolean bExecutable;
	//private long codeOffset=0L;
	//private long codeLimit=0L;
	//private long codeVirtualAddress=0L;
	//String[] symstrings;
	
	public static native String Demangle(String mangled);
}
