package com.kyhsgeekcode.disassembler;

//represents a raw file and interface

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import at.pollaknet.api.facile.Facile;
import at.pollaknet.api.facile.FacileReflector;
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException;
import at.pollaknet.api.facile.exception.SizeMismatchException;
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException;
import at.pollaknet.api.facile.symtab.symbols.scopes.Assembly;
import nl.lxtreme.binutils.elf.MachineType;

public abstract class AbstractFile implements Closeable {
    private static final String TAG = "AbstractFile";
    public static AbstractFile createInstance(String tag) throws IOException {
        File file = new File(tag);
        //file을 읽던가 mainactivity의 코드를 잘 가져와서 AbstractFile을 만든다.
        // FacileAPI거만 아니면 파일 객체와 내용만 주면 된다.
        //다시 읽는건 비효율적으로 보일 수 있지만 어쨌든 다시 읽어서 넘겨준다.
        //AfterReadFully() 참고하기!
        //다 읽고
        //AfterReadFully 로직으로 AbstractFile을 만들어 리턴한다.
        //그리고 AfterReadFully 함수는 없어질지도 모른다!
        //그러면 중복코드도 사라짐
        //행복회로
        byte[] content = MainActivity.Utils.getBytes(new FileInputStream(file));
        if (file.getPath().endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) {
            //Unity C# dll file
            Logger.v(TAG, "Found C# unity dll");
            try {
                FacileReflector facileReflector = Facile.load(file.getPath());
                //load the assembly
                Assembly assembly = facileReflector.loadAssembly();
                if (assembly != null) {
                    Logger.v(TAG, assembly.toExtendedString());
                    return new ILAssmebly(facileReflector);
                } else {
                    System.out.println("File maybe contains only resources...");
                }
            } catch (CoffPeDataNotFoundException e) {
                Logger.e(TAG, "", e);
            } catch (UnexpectedHeaderDataException e) {
                e.printStackTrace();
            } catch (SizeMismatchException e) {
                e.printStackTrace();
            }
            return new RawFile(file, content);
        } else {
            try {
                return new ELFUtil(file, content);
            } catch (Exception e) {
                //not an elf file. try PE parser
                try {
                    return new PEFile(file, content);
                } catch (NotThisFormatException f) {
                    return new RawFile(file, content);
                    //AllowRawSetup();
                    //failed to parse the file. please setup manually.
                } catch (RuntimeException f) {
                    //AlertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f);
                    return new RawFile(file, content);
                    //AllowRawSetup();
                } catch (Exception g) {
                    //AlertError("Unexpected exception: failed to parse the file. please setup manually.", g);
                    return new RawFile(file, content);
                    //AllowRawSetup();
                }
            }
        }
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public MachineType getMachineType() {
        return machineType;
    }

    @Override
    public void close() throws IOException {
        return;
    }

    public long getEntryPoint() {
        return entryPoint;
    }

    public long getCodeSectionBase() {
        return codeBase;
    }

    public long getCodeSectionLimit() {
        return codeLimit;
    }

    public long getCodeVirtAddr() {
        return codeVirtualAddress;
    }

    public List<Symbol> getSymbols() {
        if (symbols == null)
            symbols = new ArrayList<>();
        return symbols;
    }

    public List<PLT> getImportSymbols() {
        if (importSymbols == null)
            importSymbols = new ArrayList<>();
        return importSymbols;
    }

    @Override
    public String toString() {
        if (fileContents == null) {
            return "The file has not been configured. You should setup manually in the first page before you can see the details.";
        }
        StringBuilder builder = new StringBuilder(this instanceof RawFile ?
                "The file has not been configured. You should setup manually in the first page before you can see the details."
                        + System.lineSeparator()
                : "");
        builder.append(/*R.getString(R.string.FileSize)*/"File Size:").append(Integer.toHexString(fileContents.length))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.FoffsCS)).append(Long.toHexString(codeBase))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.FoffsCSEd)).append(Long.toHexString(codeLimit))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.FoffsEP)).append(Long.toHexString(codeBase + entryPoint))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.VAofCS)).append(Long.toHexString(codeVirtualAddress))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.VAofCSE)).append(Long.toHexString(codeLimit + codeVirtualAddress))
                .append(ls);
        builder.append(MainActivity.context.getString(R.string.VAofEP)).append(Long.toHexString(entryPoint + codeVirtualAddress));
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
    String ls = System.lineSeparator();
    long codeBase = 0;
    long codeLimit = 0;
    List<Symbol> symbols;
    List<PLT> importSymbols;
    byte[] fileContents;
    long entryPoint = 0;
    long codeVirtualAddress = 0;
    MachineType machineType;
    String path = "";

    public void Disassemble(MainActivity mainActivity) {
        mainActivity.DisassembleFile(0);
    }
}
