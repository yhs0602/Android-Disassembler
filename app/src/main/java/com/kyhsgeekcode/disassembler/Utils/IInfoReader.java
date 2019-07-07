package com.kyhsgeekcode.disassembler.Utils;

import java.io.InputStream;

public interface IInfoReader {
    public DisasmInfo Read(InputStream is);
}
