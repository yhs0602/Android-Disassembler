package com.kyhsgeekcode.disassembler.data;

import com.kyhsgeekcode.disassembler.data.AbstractFile;

import java.io.File;

public class RawFile extends AbstractFile {
    public RawFile(File file, byte[] filecontent) {
        this.fileContents = filecontent;
        setPath(file.getAbsolutePath());

    }

}
