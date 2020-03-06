package com.kyhsgeekcode.disassembler.utils;

import java.io.IOException;
import java.io.InputStream;

public interface IInfoReader {
    DisasmInfo Read(InputStream is) throws IOException;
}
