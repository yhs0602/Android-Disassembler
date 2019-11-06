package com.kyhsgeekcode.disassembler.Utils;

import java.io.IOException;
import java.io.InputStream;

public interface IInfoReader {
    DisasmInfo Read(InputStream is) throws IOException;
}
