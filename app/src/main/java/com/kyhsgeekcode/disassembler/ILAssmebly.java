package com.kyhsgeekcode.disassembler;

import java.io.IOException;
import java.util.List;

import at.pollaknet.api.facile.FacileReflector;
import nl.lxtreme.binutils.elf.MachineType;

public class ILAssmebly extends AbstractFile {
    FacileReflector facileReflector;

    public ILAssmebly(FacileReflector fr) {
        facileReflector = fr;
    }

    @Override
    public void setPath(String path) {
        super.setPath(path);
    }

    @Override
    public String getPath() {
        return super.getPath();
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
