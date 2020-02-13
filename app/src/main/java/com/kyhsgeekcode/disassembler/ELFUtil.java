package com.kyhsgeekcode.disassembler;

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import nl.lxtreme.binutils.elf.Elf;
import nl.lxtreme.binutils.elf.ElfClass;
import nl.lxtreme.binutils.elf.Header;
import nl.lxtreme.binutils.elf.ProgramHeader;
import nl.lxtreme.binutils.elf.SectionHeader;
import nl.lxtreme.binutils.elf.SectionType;

public class ELFUtil extends AbstractFile {
    Elf elf;
    String info = "";
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
    private String TAG = "Disassembler elfutil";

    public ELFUtil(File file, byte[] filec) throws IOException {
        elf = new Elf(file);
        setPath(file.getPath());
        fileContents = filec;
        AfterConstructor();
    }

    public static native String Demangle(String mangled);

    public static native List<PLT> ParsePLT(String filepath);

    @Override
    public void close() throws IOException {
        elf.close();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append(System.lineSeparator());
        importSymbols = getImportSymbols();
        for (PLT plt : importSymbols) {
            sb.append(plt).append(System.lineSeparator());
        }

        sb.append(elf.toString())
                //.append(Arrays.toString(symstrings))
                .append("\n").append(info);
        return sb.toString();
    }

    @Override
    public long getCodeSectionBase() {
        if (codeBase != 0) {
            return codeBase;
        }
        Log.e(TAG, "Code base 0?");
        //Do some error
        return 0L;
    }

    //MEMO - Elf file format
    // REL
    // RELA has (Offset from sh_info) Info (index to symtab at sh_link, type) value
    // SYMTAB
    // DYNSYM
    // STRTAB
    public void AfterConstructor() throws IOException {
        SectionHeader[] sections = elf.sectionHeaders;
        //assertNotNull( sections );
        ProgramHeader[] programHeaders = elf.programHeaders;
        //assertNotNull( programHeaders );
        machineType = elf.header.machineType;
        Header header = elf.header;
        //assertNotNull( header );
        if (header.entryPoint == 0) {
            //Log.i(TAG, "file " + file.getName() + "doesnt have entry point. currently set to 0x30");
            //entryPoint = 0;
        } else {
            entryPoint = header.entryPoint;
        }
        //Analyze ExportAddressTable(DynSym)
        if (elf.dynamicTable != null) {
            StringBuilder sb = new StringBuilder();
            Log.v(TAG, "size of dynamic table=" + elf.dynamicTable.length);
            long strtab = 0L;    //pointer to the string table
            long hash = 0L;
            int sym_cnt = 0;
            int i = 0;
            ByteBuffer dynsymbuffer = ByteBuffer.wrap(new byte[]{});
            ByteBuffer symbuffer = ByteBuffer.wrap(new byte[]{});
            byte[] strtable = elf.getDynamicStringTable();
            //elf.getDynamicSymbolTable();
            ArrayList<Symbol> dynsyms = new ArrayList<>();
            //byte[] symtabs=elf.getDynamicSymbolTable();
            //Syms has DynSyms
			/*try
			{
				dynsymbuffer = elf.getSection(elf.getSectionHeaderByType(SectionType.DYNSYM));
				ElfClass elfClass=elf.header.elfClass;
				if (elfClass.equals(ElfClass.CLASS_32))
				{
					while (dynsymbuffer.hasRemaining())
					{
						int name=dynsymbuffer.getInt()&0xFFFFFFFF;
						int value=dynsymbuffer.getInt()&0xFFFFFFFF;
						int size=dynsymbuffer.getInt()&0xFFFFFFFF;
						short stinfo=dynsymbuffer.get()&0x7F;
						short stother=dynsymbuffer.get()&0x7F;
						short stshndx=dynsymbuffer.getShort();
						String sym_name=Elf.getZString(strtable, name);
						Symbol symbol=new Symbol();
						symbol.name = sym_name;
						symbol.is64 = false;
						symbol.st_info = stinfo;
						symbol.st_name = name;
						symbol.st_other = stother;
						symbol.st_shndx = stshndx;
						symbol.st_size = size;
						symbol.st_value = value;
						symbol.analyze();
						dynsyms.add(symbol);
						/*sb.append(sym_name).append("=").append(Integer.toHexString(value))
						 .append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
						 *
						sb.append(symbol.toString()).append(System.lineSeparator());
					}
				}
				else
				{// 64
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
						symbol.name = sym_name;
						symbol.is64 = true;
						symbol.st_info = stinfo;
						symbol.st_name = name;
						symbol.st_other = stother;
						symbol.st_shndx = stshndx;
						symbol.st_size = size;
						symbol.st_value = value;
						symbol.analyze();
						dynsyms.add(symbol);
						/*sb.append(sym_name).append("=").append(Integer.toHexString(value))
						 .append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
						 *
						sb.append(symbol.toString()).append(System.lineSeparator());
					}
				}
			}
			catch (IllegalArgumentException |IOException e)
			{
				Log.e(TAG, "", e);
			}*/
            sb.append(System.lineSeparator()).append("syms;").append(System.lineSeparator());
            if (symbols == null)
                symbols = new ArrayList<>();
            //if (dynsyms != null)
            //symbols.addAll(dynsyms);//I hope this statement be no longer needed in the future, as they may contain duplicates
//            //First, Analyze Symbol table
//            ParseSymtab(sb, strtable);
//            // Second, Analyze Rela table
//            ArrayList<Rela> relas = new ArrayList<>();
//            ParseRela(relas);
            loadBinary(path);
            //sort it? this should be after plt parse
            Collections.sort(symbols, new Comparator<Symbol>() {
                @Override
                public int compare(Symbol p1, Symbol p2) {
                    if (p1.type == p2.type)
                        return 0;
                    if (p1.type == Symbol.Type.STT_FUNC)
                        return -1;
                    if (p2.type == Symbol.Type.STT_FUNC)
                        return 1;
                    return 0;
                }
            });
            for (Symbol sym : symbols) {
                sb.append(sym.toString());
            }
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
//            ByteBuffer relBuf = elf.getSection(elf.getSectionHeaderByType(SectionType.REL));
//            ElfClass elfClass = elf.header.elfClass;
//            if (elfClass.equals(ElfClass.CLASS_32)) {
//                while (relBuf.remaining() > 0) {
					/*t y p e d e f s t r u c t {
						E l f 3 2 _ A d d r r _ o f f s e t ;
						E l f 3 2 _ W o r d r _ i n f o ;
						} E l f 3 2 _ R e l ;
						t y p e d e f s t r u c t {
							E l f 3 2 _ A d d r  r _ o f f s e t ;
							E l f 3 2 _ W o r d  r _ i n f o ;
							E l f 3 2 _ S w o r d  r _ a d d e n d ;
						} E l f 3 2 _ R e l a;
					 # d e f i n e E L F 3 2 _ R _ S Y M ( i ) ( ( i ) > > 8 )
					 # d e f i n e E L F 3 2 _ R _ T Y P E ( i ) ( ( u n s i g n e d c h a r ) ( i ) )
					 # d e f i n e E L F 3 2 _ R _ I N F O ( s , t ) ( ( ( s ) < < 8 ) + ( u n s i g n e d c h a r ) ( t ) )
					*/
//                    int offset = relBuf.getInt();
//                    int info = relBuf.getInt();
//                    int symidx = info >> 8;
//                    int type = info & 0x7F;
//                    Log.v(TAG, "offset=" + Integer.toHexString(offset) + "symidx=" + symidx + "&type=" + type + "&info=" + info);
					/*
					Intel
					 Name Value  Field  Calculation
					 _ __________________________________________________
					 R_386_NONE 0 none none
					 R_386_32 1 word32 S + A R_386_PC32
					 2 word32 S + A - P R_386_GOT32
					 3 word32 G + A - P R_386_PLT32
					 4 word32 L + A - P R_386_COPY
					 5 none none R_386_GLOB_DAT
					 6 word32 S R_386_JMP_SLOT
					 7 word32 S R_386_RELATIVE
					 8 word32 B + A R_386_GOTOFF
					 9 word32 S + A - GOT R_386_GOTPC
					 10 word32 GOT + A - P
					 _ __________________________________________________
					 Tool Interface Standards (TIS)  Portable  Formats Specification, Version 1.1
					 ARM
					 Code  Name Type Class
					 0 R_ARM_NONE Static Operation Miscellaneous
					 1 R_ARM_PC24 Deprecated  ARM
					 2 R_ARM_ABS32 Static (( S + A ) | T)P Data
					 3 R_ARM_REL32 Static ( S + A ) | T Data
					 4 R_ARM_LDR_PC_G0 Static (( S + A ) | T)P ARM
					 5 R_ARM_ABS16 Static S + A P Data
					 6 R_ARM _ABS12 Static S + A ARM
					 7 R_ARM_THM_ABS5 Static S + A Thumb16
					 8 R_ARM_ABS8 Static S + A Data
					 9 R_ARM_SBREL32 Static S + A Data (( S + A ) | T)B(S)
					 10 R_ARM_THM_CALL Static Thumb32 ((S + A) | T) – P
					 11 R_ARM_THM_PC8 Static Thumb16 S + A – Pa
					 12 R_ARM_BREL_ADJ Dynamic Data ΔB(S) + A
					 13 R_ARM_TLS_DESC Dynamic Data
					 14 R_ARM_THM_SWI8 Obsolete Encodings reserved for future Dynamic relocations
					 15 R_ARM_XPC25 Obsolete
					 16 R_ARM_THM_XPC22 Obsolete
					 17 R_ARM_TLS_DTPMOD32 Dynamic Data Module[S]
					 18 R_ARM_TLS_DTPOFF32 Dynamic Data S + A – TLS
					 19 R_ARM_TLS_TPOFF32 Dynamic Data S + A – tp
					 20 R_ARM_COPY Dynamic Miscellaneous
					 21 R_ARM_GLOB_DAT Dynamic Data (S + A) | T
					 22 R_ARM_JUMP_SLOT Dynamic Data (S + A) | T
					 23 R_ARM_RELATIVE Dynamic Data B(S) + A  [Note: see Table 4-18]
					 24 R_ARM_GOTOFF32 Static Data ((S + A) | T) – GOT_ORG
					 25 R_ARM_BASE_PREL Static Data B(S) + A – P
					 26 R_ARM_GOT_BREL Static Data GOT(S) + A – GOT_ORG
					 27 R_ARM_PLT32 Deprecated ARM ((S + A) | T) – P
					 28 R_ARM_CALL Static ARM ((S + A) | T) – P
					 29 R_ARM_JUMP24 Static ARM ((S + A) | T) – P
					 30 R_ARM_THM_JUMP24 Static Thumb32 ((S + A) | T) – P
					 31 R_ARM_BASE_ABS Static Data B(S) + A
					 32 R_ARM_ALU_PCREL_7_0 Obsolete  Note – Legacy (ARM ELF B02) names have been retained for these obsolete relocations.
					 33 R_ARM_ALU_PCREL_15_8 Obsolete
					 34 R_ARM_ALU_PCREL_23_15 Obsolete
					 35 R_ARM_LDR_SBREL_11_0_NC Deprecated ARM S + A – B(S)
					 36 R_ARM_ALU_SBREL_19_12_NC Deprecated ARM S + A – B(S)
					 37 R_ARM_ALU_SBREL_27_20_CK Deprecated ARM S + A – B(S)
					 38 R_ARM_TARGET1 Static Miscellaneous (S + A) | T or  ((S + A) | T) – P
					 39 R_ARM_SBREL31 Deprecated Data ((S + A) | T) – B(S)
					 40 R_ARM_V4BX Static Miscellaneous
					 41 R_ARM_TARGET2 Static Miscellaneous
					 42 R_ARM_PREL31 Static Data ((S + A) | T) – P
					 ARM  IHI  0044F Copyright  ©  2003-2009,  2012,  2014-2015  ARM  Limited.  All  rights  reserved. Page  26  of  48
					 Table  4-18,  Dynamic  relocations
					 Code  Relocation  Comment
					 17 (S  ≠  0) R_ARM_TLS_DTPMOD32 Resolves  to the module number  of  the module  defining the specified TLS  symbol,  S. (S  =  0)  Resolves  to the module number  of  the current  module (ie.  the module containing this  relocation).
					 18 R_ARM_TLS_DTPOFF32 Resolves  to  the  index  of  the specified  TLS  symbol  within  its  TLS  block
					 19 R_ARM_TLS_TPOFF32  (S  ≠  0)  Resolves  to the  offset  of  the specified TLS  symbol,  S,  from  the  Thread Pointer, TP.
										   (S  =  0)  Resolves  to the  offset  of  the  current  module’s  TLS  block  from  the Thread Pointer,  TP
										   (the addend  contains  the offset  of  the  local  symbol  within the TLS  block).
					 20 R_ARM_COPY  See below
					 21 R_ARM_GLOB_DAT Resolves  to  the  address  of  the specified symbol
					 22 R_ARM_JUMP_SLOT Resolves  to  the  address  of  the specified symbol
					 23 R_ARM_RELATIVE (S  ≠  0)  B(S)  resolves  to  the  difference between  the  address  at  which the segment  defining the symbol  S  was  loaded  and the address  at  which it  was linked. l
								       (S =  0)  B(S)  resolves  to  the  difference between  the  address  at  which the segment  being relocated  was  loaded  and the address  at  which it  was  linked
					*/
//                }
//            }
            //Now prepare IAT(PLT/GOT)
            //get .got
//            for (SectionHeader hdr : sections) {
//                if (".plt".equalsIgnoreCase(hdr.getName())) {
                    //plt is code
//					 000173ec __android_log_print@plt:
//					 173ec:       e28fc600        add     ip, pc, #0, 12  ; ip!=pc?
//					 173f0:       e28cca11        add     ip, ip, #69632  ; addr of got?
//					 173f4:       e5bcf9f4        ldr     pc, [ip, #2548]!; index=2548
//						 000173f8 sleep@plt:
//					 173f8:       e28fc600        add     ip, pc, #0, 12
//					 173fc:       e28cca11        add     ip, ip, #69632
//					 17400:       e5bcf9ec        ldr     pc, [ip, #2540]!
//					 ...
//                    ByteBuffer buf = elf.getSection(hdr);
//                }
//            }
//            dynsymbuffer = elf.getSection(elf.getSectionHeaderByType(SectionType.PROGBITS));
            // importSymbols=ParsePLT(path);
            info = sb.toString();
            //Log.i(TAG, "info=" + info);
        }
        Log.v(TAG, "Checking code section");
        for (SectionHeader sh : elf.sectionHeaders) {
            Log.v(TAG, "type=" + sh.type.toString() + "name=" + sh.getName());
            if (sh.type.equals(SectionType.PROGBITS)) {
                Log.v(TAG, "sh.type.equals Progbits");
                String name = sh.getName();
                if (name != null) {
                    Log.i(TAG, "name nonnull:name=" + name);
                    if (name.equals(".text")) {
                        codeBase = sh.fileOffset;
                        codeLimit = codeBase + sh.size;
                        codeVirtualAddress = sh.virtualAddress;
                    }
                }
            }
        }
    }

    //private long codeOffset=0L;
    //private long codeLimit=0L;
    //private long codeVirtualAddress=0L;
    //String[] symstrings;
    private void ParseRela(ArrayList<Rela> relas) throws IOException {
        SectionHeader relaSec = elf.getSectionHeaderByType(SectionType.RELA);
        if (relaSec != null) {
            ByteBuffer relaBuf = elf.getSection(relaSec);
            int targetSection = relaSec.info;
            int sourceSymtab = relaSec.link;
            while (relaBuf.hasRemaining()) {
                long r_offset = relaBuf.getLong();      //unsigned, byte offset from targetSection
                long r_info = relaBuf.getLong();        //unsigned, index to sourceSymtab
                int index = (int) (long) (r_info >> 32 & 0xFFFFFFFF);
                Symbol symbol = symbols.get(index);
                long r_addend = relaBuf.getLong();     //signed, delta
                Rela rela = new Rela();
                rela.targetSection = targetSection;
                rela.symsection = sourceSymtab;
                rela.index = index;
                rela.symbol = symbol;
                rela.r_offset = r_offset;
                rela.r_addend = r_addend;
                rela.r_info = r_info;
                rela.type = (int) (r_info & 0xFFFFFFFF);
                relas.add(rela);
            }
        }
    }

    private void ParseSymtab(StringBuilder sb, byte[] strtable) {
        ByteBuffer symbuffer;
        try {
            symbuffer = elf.getSection(elf.getSectionHeaderByType(SectionType.SYMTAB));
            ElfClass elfClass = elf.header.elfClass;
            symbols = new ArrayList<>();
            if (elfClass.equals(ElfClass.CLASS_32)) {
                while (symbuffer.hasRemaining()) {
                    int name = symbuffer.getInt();
                    int value = symbuffer.getInt();
                    int size = symbuffer.getInt();
                    short stinfo = symbuffer.get();
                    short stother = symbuffer.get();
                    short stshndx = symbuffer.getShort();
                    String sym_name = Elf.getZString(strtable, name);
                    Symbol symbol = new Symbol();
                    symbol.name = sym_name;
                    symbol.is64 = false;
                    symbol.st_info = stinfo;
                    symbol.st_name = name;
                    symbol.st_other = stother;
                    symbol.st_shndx = stshndx;
                    symbol.st_size = size;
                    symbol.st_value = value;
                    symbol.analyze();
                    symbols.add(symbol);
                    /*sb.append(sym_name).append("=").append(Integer.toHexString(value))
                     .append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
                     */
                    sb.append(symbol.toString()).append(System.lineSeparator());
                }
            } else {// 64
                while (symbuffer.hasRemaining()) {
                    int name = symbuffer.getInt();
                    short stinfo = symbuffer.get();
                    short stother = symbuffer.get();
                    short stshndx = symbuffer.getShort();
                    long value = symbuffer.getLong();
                    long size = symbuffer.getLong();
                    String sym_name = Elf.getZString(strtable, name);
                    Symbol symbol = new Symbol();
                    symbol.name = sym_name;
                    symbol.is64 = true;
                    symbol.st_info = stinfo;
                    symbol.st_name = name;
                    symbol.st_other = stother;
                    symbol.st_shndx = stshndx;
                    symbol.st_size = size;
                    symbol.st_value = value;
                    symbol.analyze();
                    symbols.add(symbol);
                    /*	sb.append(sym_name).append("=").append(Integer.toHexString(value))
                     .append(";size=").append(size).append(";").append(stinfo).append(";").append(stshndx)
                     */
                    sb.append(symbol.toString()).append(System.lineSeparator());
                }
            }
        } catch (IllegalArgumentException | IOException | StringIndexOutOfBoundsException e) {
            Log.e(TAG, "", e);
        }
    }

    native void loadBinary(String path);

    public void addSymbol(Symbol symbol) {
        symbol.analyze();
        symbols.add(symbol);
    }
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
	 
	 /*
	 public ELFUtil(FileChannel channel, byte[] filec) throws IOException
	 {
	 super(null);
	 elf = new Elf(channel);
	 fileContents = filec;
	 AfterConstructor();
	 }*/
