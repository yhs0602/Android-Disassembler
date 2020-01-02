package com.kyhsgeekcode.disassembler.data;

import com.kyhsgeekcode.disassembler.MainActivity;
import com.kyhsgeekcode.disassembler.data.AbstractFile;
import com.kyhsgeekcode.disassembler.data.PLT;
import com.kyhsgeekcode.disassembler.data.Symbol;

import java.io.IOException;
import java.util.List;

import at.pollaknet.api.facile.FacileReflector;
import nl.lxtreme.binutils.elf.MachineType;

public class ILAssmeblyFile extends AbstractFile {
    FacileReflector facileReflector;

    public ILAssmeblyFile(FacileReflector fr) {
        facileReflector = fr;
    }

    @Override
    public MachineType getMachineType() {
        return super.getMachineType();
    }

    @Override
    public void close() throws IOException {
        super.close();
    }

    @Override
    public long getEntryPoint() {
        return super.getEntryPoint();
    }

    @Override
    public long getCodeSectionBase() {
        return super.getCodeSectionBase();
    }

    @Override
    public long getCodeSectionLimit() {
        return super.getCodeSectionLimit();
    }

    @Override
    public long getCodeVirtAddr() {
        return super.getCodeVirtAddr();
    }

    @Override
    public List<Symbol> getSymbols() {
        return super.getSymbols();
    }

    @Override
    public List<PLT> getImportSymbols() {
        return super.getImportSymbols();
    }

    @Override
    public String toString() {
        return super.toString();
    }

    @Override
    public void Disassemble(MainActivity mainActivity) {

    }
}
