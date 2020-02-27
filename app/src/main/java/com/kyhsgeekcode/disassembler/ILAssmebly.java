package com.kyhsgeekcode.disassembler;

import java.io.IOException;

import at.pollaknet.api.facile.FacileReflector;

public class ILAssmebly extends AbstractFile {
    FacileReflector facileReflector;

    public ILAssmebly(FacileReflector fr) {
        facileReflector = fr;
    }


    @Override
    public void close() throws IOException {
        super.close();
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
    public String toString() {
        return super.toString();
    }

}
