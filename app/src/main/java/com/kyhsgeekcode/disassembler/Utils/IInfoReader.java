package com.kyhsgeekcode.disassembler.Utils;

import java.io.IOException;
import java.io.InputStream;

public interface IInfoReader {
    public DisasmInfo Read(InputStream is) throws IOException;
}
