package com.kyhsgeekcode.disassembler.utils2;

import java.io.IOException;
import java.io.InputStream;

public interface IInfoReader {
    DisasmInfo Read(InputStream is) throws IOException;
}
