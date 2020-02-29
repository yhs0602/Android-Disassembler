package com.kyhsgeekcode.disassembler;

import android.util.Log;

import org.boris.pecoff4j.DOSHeader;
import org.boris.pecoff4j.ExportDirectory;
import org.boris.pecoff4j.ImageData;
import org.boris.pecoff4j.ImportDirectory;
import org.boris.pecoff4j.ImportDirectoryEntry;
import org.boris.pecoff4j.OptionalHeader;
import org.boris.pecoff4j.PE;
import org.boris.pecoff4j.RVAConverter;
import org.boris.pecoff4j.io.PEParser;
import org.jetbrains.annotations.NotNull;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import nl.lxtreme.binutils.elf.Elf;
import nl.lxtreme.binutils.elf.MachineType;

public class PEFile extends AbstractFile {
    PE pe;
    ArrayList<TLS> tlss = new ArrayList<>();
    private String TAG = "Disassembler PE";

    public PEFile(File file, byte[] filec) throws IOException, NotThisFormatException {
        path = file.getPath();
        try {
            pe = PEParser.parse(file);
        } catch (NegativeArraySizeException e) {
            throw new NotThisFormatException(/*"PECOFFJ's Parser threw an exception."*/);
        } catch (EOFException e) {
            throw new RuntimeException("The PE parser threw EOFException. The file may be corrupted.");
        }
        if (pe == null || pe.getSignature() == null || !pe.getSignature().isValid()) {
            throw new NotThisFormatException();
        }
        DOSHeader dosh = pe.getDosHeader();
        ImageData imd = pe.getImageData();
        OptionalHeader oph = pe.getOptionalHeader();
        int machine = pe.getCoffHeader().getMachine();
        //byte[] bytes=imd.getArchitecture();
        //int machine=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort()&0xFFFF;
        setMachineType(getMachineTypeFromPE(machine));
        setCodeSectionBase(oph.getBaseOfCode());
        setCodeSectionLimit(getCodeSectionBase() + oph.getSizeOfCode());
        setCodeVirtAddr(oph.getImageBase() + getCodeSectionBase());
        setEntryPoint(oph.getAddressOfEntryPoint());
        fileContents = filec;

        getSymbols().clear();
        getImportSymbols().clear();
        //Parse IAT
        ImportDirectory idir = imd.getImportTable();
        int numofIAT = idir.size();
        RVAConverter rvc = pe.getSectionTable().getRVAConverter();
        for (int i = 0; i < numofIAT; i++)//iterate over dlls
        {
            ImportDirectoryEntry ide = idir.getEntry(i);//dll
            if (ide == null)
                continue;//null dll

            String dllname = Elf.getZString(filec, rvc.convertVirtualAddressToRawDataPointer(ide.getNameRVA()));//idir.getName(i);//get dll name? !! Not implemented method!!!!
            Log.v(TAG, dllname);
            long originalFirstThunkRaw = rvc.convertVirtualAddressToRawDataPointer(ide.getImportLookupTableRVA());//OriginalFirstThunk
            long firstThunkRaw = rvc.convertVirtualAddressToRawDataPointer(ide.getImportAddressTableRVA());
            ByteBuffer buf = ByteBuffer.wrap(filec, (int) originalFirstThunkRaw, (int) (filec.length - originalFirstThunkRaw)).order(ByteOrder.LITTLE_ENDIAN);
            int off = 0;
            //Read by dword!
            for (; ; ) {
                long data = buf.getInt() & 0xFFFFFFFF;
                if (data == 0)
                    break;
                PLT plt = new PLT();
                if ((data & 0x80000000) != 0) {
                    //MSB 1;Ordinal
                    int ordinal = (int) (data & 0x7FFFFFFF);
                } else {
                    //Name RVA
                    //WORD hint;
                    //CHAR name[1];
					/*ByteBuffer INT=ByteBuffer.wrap(filec,(int)data,(int)(filec.length-data));
					 INT.getShort();*/
                    String funcname = Elf.getZString(filec, rvc.convertVirtualAddressToRawDataPointer((int) data) + 2);
                    //Log.v(TAG,dllname+"."+funcname);
                    plt.name = dllname + "." + funcname;
                    plt.address = firstThunkRaw + off;
                    getImportSymbols().add(plt);
                    Log.v(TAG, plt.toString());
                }
                off += 4;
            }
        }
        //Parse EAT
        ExportDirectory edir = imd.getExportTable();
        if (edir != null) {
            long numofExports = edir.getAddressTableEntries();//getNumberOfNamePointers();
            long funcAddrRaw = rvc.convertVirtualAddressToRawDataPointer((int) edir.getExportAddressTableRVA());
            long funcNameRaw = rvc.convertVirtualAddressToRawDataPointer((int) edir.getNamePointerRVA());
            long funcOrdinalRaw = rvc.convertVirtualAddressToRawDataPointer((int) edir.getOrdinalTableRVA());
            ByteBuffer funcnamePointers = ByteBuffer.wrap(filec, (int) funcNameRaw, (int) (filec.length - funcNameRaw)).order(ByteOrder.LITTLE_ENDIAN);//len eq num of name
            ByteBuffer funcOrdinalPointers = ByteBuffer.wrap(filec, (int) funcOrdinalRaw, (int) (filec.length - funcOrdinalRaw)).order(ByteOrder.LITTLE_ENDIAN);//len eq num of name
            int ordinalbase = (int) edir.getOrdinalBase();
            Log.v(TAG, "OrdinalBase=" + ordinalbase);
            //RVAConverter rvc=pe.getSectionTable().getRVAConverter();
            for (int i = 0; i < numofExports; i++)//iterate over functions
            {
                Symbol sym = new Symbol();
                try {
                    sym.name = Elf.getZString(filec, rvc.convertVirtualAddressToRawDataPointer(funcnamePointers.getInt() & 0x7FFFFFFF));
                } catch (StringIndexOutOfBoundsException e) {
                    Log.e(TAG, "", e);
                    sym.name = "ordinal?";
                }

                //funcnamePointers.getInt();
                int ordinal = funcOrdinalPointers.getShort() & 0x7FFF;
                long addraddr = funcAddrRaw + 4 * (ordinal - ordinalbase);
                Log.v(TAG, "addraddr=" + addraddr);
                sym.st_value = ByteBuffer.wrap(filec, (int) addraddr, (int) (filec.length - addraddr)).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0x7FFFFFFF;
                Log.v(TAG, sym.toString());
                sym.type = Symbol.Type.STT_FUNC;
                sym.bind = Symbol.Bind.STB_GLOBAL;
                sym.demangled = sym.name;
                getSymbols().add(sym);
            }
        }
        //parse TLS
        byte[] tlsb = imd.getTlsTable();
        if (tlsb != null) {
            ByteBuffer tlsBuf = ByteBuffer.wrap(tlsb).order(ByteOrder.LITTLE_ENDIAN);
            /*Dword 6*/
            while (tlsBuf.remaining() > 0) {
                int StartAddressOfRawData = tlsBuf.getInt();
                int EndAddressOfRawData = tlsBuf.getInt();
                int AddressOfIndex = tlsBuf.getInt();
                int AddressOfCallBacks = tlsBuf.getInt();
                int SizeOfZeroFill = tlsBuf.getInt();
                int Characteristics = tlsBuf.getInt();
                TLS tls = new TLS();
                tls.StartAddressOfRawData = StartAddressOfRawData;
                tls.EndAddressOfRawData = EndAddressOfRawData;
                tls.AddressOfIndex = AddressOfIndex;
                tls.AddressOfCallBacks = AddressOfCallBacks;
                tls.SizeOfZeroFill = SizeOfZeroFill;
                tls.Characteristics = Characteristics;
                tlss.add(tls);
            }
        }

    }

    //https://docs.microsoft.com/ko-kr/windows/desktop/api/winnt/ns-winnt-_image_file_header
    private MachineType getMachineTypeFromPE(int machine) {
        int h = org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_I386;
        switch (machine) {
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
                return MachineType.ARM;
            case org.boris.pecoff4j.constant.MachineType.IMAGE_FILE_MACHINE_WCEMIPSV2:
                return MachineType.MIPS;
        }
        //I don't know
        return nl.lxtreme.binutils.elf.MachineType.i386;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(super.toString());
        builder.append(ls).append(ls);
        builder.append("======Export Table=====");
        builder.append(ls);
        for (Symbol sym : getSymbols()) {
            builder.append(sym.toString());
            builder.append(ls);
        }
        builder.append(ls);
        builder.append("======Import Table=====");
        builder.append(ls);
        for (PLT plt : getImportSymbols()) {
            builder.append(plt.toString());
            builder.append(ls);
        }

        builder.append("======Thread Local Storage Table=====");
        builder.append(ls);
        for (TLS tls : tlss) {
            builder.append(tls.toString());
            builder.append(ls);
        }
        builder.append(pe.toString());
        return builder.toString();
    }

    class TLS {
        int StartAddressOfRawData;
        int EndAddressOfRawData;
        int AddressOfIndex;
        int AddressOfCallBacks;
        int SizeOfZeroFill;
        int Characteristics;

        @NotNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("TLS at ");
            sb.append(StartAddressOfRawData);
            sb.append("~");
            sb.append(EndAddressOfRawData);
            sb.append("(Index at ");
            sb.append(AddressOfIndex);
            sb.append("), callback at ");
            sb.append(AddressOfCallBacks);
            sb.append(", zerofillsize=");
            sb.append(SizeOfZeroFill);
            sb.append(", characteristics=");
            sb.append(Characteristics);
            return sb.toString();
        }

    }
}
