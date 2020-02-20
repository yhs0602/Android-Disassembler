package com.kyhsgeekcode.disassembler;

import java.io.File;

public class RawFile extends AbstractFile {
    public RawFile(File file, byte[] filecontent) {
        this.fileContents = filecontent;
        path = file.getPath();

    }

}
