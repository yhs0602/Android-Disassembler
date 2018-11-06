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
	public PEFile(File file,byte[] filec) throws IOException
	{
		pe = PEParser.parse(file);
		DOSHeader dosh=pe.getDosHeader();
		ImageData imd= pe.getImageData();
		OptionalHeader oph=pe.getOptionalHeader();
		byte[] bytes=imd.getArchitecture();
		int machine=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort()&0xFFFF;
		machineType=getMachineTypeFromPE(machine);
		codeBase=oph.getBaseOfCode();
		codeLimit=codeBase+oph.getSizeOfCode();
		codeVirtualAddress=oph.getImageBase()+codeBase;
		entryPoint=oph.getAddressOfEntryPoint();
		fileContents=filec;
		//Setup symbol table
		symbols=new ArrayList<>();
		ExportDirectory ed=imd.getExportTable();
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
			Log.v(TAG,Elf.getZString(fileContents,namepos));
		}
		for(int i=0;i<id.size();++i)
		{
			String name= id.getName(i);
			ImportDirectoryEntry a=id.getEntry(i);
			ImportDirectoryTable t=id.getAddressTable(i);
			ImportEntry r= t.getEntry(0);
		
		}
	}
	//https://docs.microsoft.com/ko-kr/windows/desktop/api/winnt/ns-winnt-_image_file_header
	private MachineType getMachineTypeFromPE(int machine)
	{
		switch(machine)
		{
			case 0x014c:
				return MachineType.i386;
			case 0x0200:
				return MachineType.IA_64;
			case 0x8664:
				return MachineType.x86_64;		
		}
		//I don't know
		return MachineType.ARM;
	}
	PE pe;
	
}
