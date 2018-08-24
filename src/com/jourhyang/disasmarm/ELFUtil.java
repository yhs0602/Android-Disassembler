package com.jourhyang.disasmarm;
import android.util.*;
import java.io.*;
import java.util.*;
import nl.lxtreme.binutils.elf.*;
public class ELFUtil implements Closeable
{

	private String TAG="Diasassembler elfutil";

	@Override
	public void close() throws IOException
	{
		// TODO: Implement this method
		elf.close();
	}
	
	Elf elf;
	public long getEntryPoint()
	{
		return entryPoint;
	}
	public String toString()
	{
		return new StringBuilder(elf.toString())
					.append(Arrays.toString(symstrings)).toString();
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
		/* Callback for dl_iterate_phdr.
		 * Is called by dl_iterate_phdr for every loaded shared lib until something
		 * else than 0 is returned by one call of this function.
		 */
		//int retrieve_symbolnames(struct dl_phdr_info* info, size_t info_size, void* symbol_names_vector) 
		{

			/* ElfW is a macro that creates proper typenames for the used system architecture
			 * (e.g. on a 32 bit system, ElfW(Dyn*) becomes "Elf32_Dyn*") */
			//ElfW(Dyn*) dyn;
			//ElfW(Sym*) sym;
			//ElfW(Word*) hash;

			//char* strtab = 0;
			//char* sym_name = 0;
			//ElfW(Word) sym_cnt = 0;

			/* the void pointer (3rd argument) should be a pointer to a vector<string>
			 * in this example -> cast it to make it usable */
			//vector<string>* symbol_names = reinterpret_cast<vector<string>*>(symbol_names_vector);

			/* Iterate over all headers of the current shared lib
			 * (first call is for the executable itself) */
			//Elf elf=elfUtil.elf;
			//elf.getSectionHeaderByType(SectionType.DYNAMIC);
			/*for(SectionHeader sh:sections)
			{
				if(sh.type.equals(SectionType.DYNAMIC))
				{
					//long dyn=sh.fileOffset;
					ByteBuffer buf=elf.getSection(sh);
					int entnum=(int)(sh.size/sh.entrySize);
					symstrings=new String[entnum];
					for(int i=0;i<entnum;++i)
					{
						byte [] bytes=new byte[(int)sh.entrySize];
						buf.get(bytes);
						symstrings[i]=new String(bytes);
					}
					//elf.dynamicTable
				}
			}*/
			StringBuilder sb=new StringBuilder();
			for(DynamicEntry de:elf.dynamicTable)
			{
				DynamicEntry.Tag tag=de.getTag();
				long strtab=0L;
				long hash=0L;
				int sym_cnt=0;
				if(tag==null)
				{
					Log.v(TAG,"Tag null");
					break;
				}
				if(de.getTag().equals(DynamicEntry.Tag.NULL))	
				{
					Log.v(TAG,"Tag NULL");
					break;
				}
				if(tag.equals(DynamicEntry.Tag.HASH))
				{
					hash=de.getValue();
				}
				else if(tag.equals(DynamicEntry.Tag.STRTAB))
				{
					strtab=de.getValue();
				}
				else if(tag.equals(DynamicEntry.Tag.SYMTAB))
				{
					long sym=de.getValue();
			//		int sym_index=0;
					for(int sym_index=0;sym_index<sym_cnt;sym_index++)
					{
						String sym_name=new String(fileContents,(int)strtab+fileContents[sym+sym_index],64);
						//	sym_name = &strtab[sym[sym_index].st_name];
						sb.append(sym_name).append("\n");
					}
				}
					
			}
		//	for (size_t header_index = 0; header_index < info->dlpi_phnum; header_index++)
		//	{

				/* Further processing is only needed if the dynamic section is reached */
		//		if (info->dlpi_phdr[header_index].p_type == PT_DYNAMIC)
			//	{

					/* Get a pointer to the first entry of the dynamic section.
					 * It's address is the shared lib's address + the virtual address */
					//dyn = (ElfW(Dyn)*)(info->dlpi_addr +  info->dlpi_phdr[header_index].p_vaddr);

					/* Iterate over all entries of the dynamic section until the
					 * end of the symbol table is reached. This is indicated by
					 * an entry with d_tag == DT_NULL.
					 *
					 * Only the following entries need to be processed to find the
					 * symbol names:
					 *  - DT_HASH   -> second word of the hash is the number of symbols
					 *  - DT_STRTAB -> pointer to the beginning of a string table that
					 *                 contains the symbol names
					 *  - DT_SYMTAB -> pointer to the beginning of the symbols table
					 */
				//	while(dyn->d_tag != DT_NULL)
			//		{
					//	if (dyn->d_tag == DT_HASH)
					//	{
				//			/* Get a pointer to the hash */
				//			hash = (ElfW(Word*))dyn->d_un.d_ptr;
//
							/* The 2nd word is the number of symbols */
				//			sym_cnt = hash[1];

				//		}
					//	else if (dyn->d_tag == DT_STRTAB)
					//	{
				//			/* Get the pointer to the string table */
					//		strtab = (char*)dyn->d_un.d_ptr;
						//}
					//	else if (dyn->d_tag == DT_SYMTAB)
					//	{
							/* Get the pointer to the first entry of the symbol table */
							//sym = (ElfW(Sym*))dyn->d_un.d_ptr;


							/* Iterate over the symbol table */
							//for (ElfW(Word) sym_index = 0; sym_index < sym_cnt; sym_index++)
						//	{
								/* get the name of the i-th symbol.
								 * This is located at the address of st_name
								 * relative to the beginning of the string table. */
							//	sym_name = &strtab[sym[sym_index].st_name];

							//	symbol_names->push_back(string(sym_name));
							//}
						//}

						/* move pointer to the next entry */
						//dyn++;
					//}
				//}
		//	}

			/* Returning something != 0 stops further iterations,
			 * since only the first entry, which is the executable itself, is needed
			 * 1 is returned after processing the first entry.
			 *
			 * If the symbols of all loaded dynamic libs shall be found,
			 * the return value has to be changed to 0.
			 */
			//return 1;

		}
		info=sb.toString();
		//CodeBase=
		//System.out.printf( "Entry point: 0x%x\n", header.entryPoint );
	}
	String info="";
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
	String[] symstrings;
}
