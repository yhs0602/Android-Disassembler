package com.kyhsgeekcode.disassembler.util;

import java.io.IOException;
import java.io.InputStream;

public interface IInfoReader {
    DisasmInfo Read(InputStream is) throws IOException;
}
