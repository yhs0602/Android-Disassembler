package com.kyhsgeekcode.disassembler;

import java.io.*;
import org.boris.pecoff4j.*;
import org.boris.pecoff4j.io.*;
import java.nio.*;
import nl.lxtreme.binutils.elf.*;
import java.util.*;
import android.util.*;

public class PEFile extends AbstractFile
{
	private String TAG="Disassembler PE";
	public PEFile(File file,byte[] filec) throws IOException, NotThisFormatException
	{
		pe = PEParser.parse(file);
		
		if(pe==null||pe.getSignature()==null||!pe.getSignature().isValid())
		{
			throw new NotThisFormatException();
		}
		DOSHeader dosh=pe.getDosHeader();
		ImageData imd= pe.getImageData();
		OptionalHeader oph=pe.getOptionalHeader();
		int machine=pe.getCoffHeader().getMachine();
		//byte[] bytes=imd.getArchitecture();
		//int machine=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort()&0xFFFF;
		machineType=getMachineTypeFromPE(machine);
		codeBase=oph.getBaseOfCode();
		codeLimit=codeBase+oph.getSizeOfCode();
		codeVirtualAddress=oph.getImageBase()+codeBase;
		entryPoint=oph.getAddressOfEntryPoint();
		fileContents=filec;
		//Setup symbol table
		symbols=new ArrayList<>();
		/*ExportDirectory ed=imd.getExportTable();
		ImportDirectory id=imd.getImportTable();
		long numfuncs=ed.getAddressTableEntries();
		long numnames=ed.getNumberOfNamePointers();
		long addressOfFunctions=ed.getExportAddressTableRVA();
		long namesaddr=ed.getNamePointerRVA();
		long ordinaladdr=ed.getOrdinalTableRVA();
		//namesaddr->value->value=nameRVA-->value
		RVAConverter rvc= pe.getSectionTable().getRVAConverter();
		addressOfFunctions=rvc.convertVirtualAddressToRawDataPointer((int)addressOfFunctions);
		namesaddr=rvc.convertVirtualAddressToRawDataPointer((int)namesaddr);
		ordinaladdr=rvc.convertVirtualAddressToRawDataPointer((int)ordinaladdr);
		ByteBuffer bufNames=ByteBuffer.wrap(fileContents);
		ByteBuffer bufvalues=ByteBuffer.wrap(fileContents);
		bufNames.position((int)namesaddr);
		for(int i=0;i<numnames;++i)
		{
			int namepos=bufNames.getInt();
			//Log.v(TAG,Elf.getZString(fileContents,namepos));
		}
		for(int i=0;i<id.size();++i)
		{
			String name= id.getName(i);
			ImportDirectoryEntry a=id.getEntry(i);
			ImportDirectoryTable t=id.getAddressTable(i);
			ImportEntry r= t.getEntry(0);
		
		}*/
	}
	//https://docs.microsoft.com/ko-kr/windows/desktop/api/winnt/ns-winnt-_image_file_header
	private MachineType getMachineTypeFromPE(int machine)
	{
		int h=org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_I386;
		switch(machine)
		{
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_I386:
				return MachineType.i386;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_IA64:
				return MachineType.IA_64;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_AMD64:
				return MachineType.x86_64;	
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_AM33:
				return MachineType.ARC;//?
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_ARM:
				return MachineType.ARM;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_EBC:
				return MachineType.XTENSA;//?
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_M32R:
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_MIPS16:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_MIPSFPU:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_MIPSFPU16:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_POWERPC:
				return MachineType.PPC;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_POWERPCFP:
				return MachineType.PPC;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_R4000:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_SH3:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_SH3DSP:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_SH4:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_SH5:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_THUMB:
				return MachineType.MIPS;
			case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_WCEMIPSV2:
				return MachineType.MIPS;
		}
		//I don't know
		return nl.lxtreme.binutils.elf.MachineType.i386;
	}
	PE pe;
	
}
