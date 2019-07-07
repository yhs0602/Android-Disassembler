package com.kyhsgeekcode.disassembler.Utils.Olly;

import com.kyhsgeekcode.disassembler.Utils.DisasmInfo;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

public class UDDWriter {
    public static void WriteUDD(OutputStream os, DisasmInfo info) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        WriteSignature(dos);

        WriteFinish(dos);
        dos.close();
    }

    private static void WriteTag(DataOutputStream dos, int tag, int size, byte[] data) throws IOException {
        dos.writeInt(tag);
        dos.writeInt(size);
        dos.write(data);
    }

    private static void WriteSignature(DataOutputStream dos) throws IOException {
        try {
            byte[] bytes = "Module info file va1.7".getBytes("utf8");
            WriteTag(dos, 0x00646F4D, bytes.length, bytes);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static void WriteFinish(DataOutputStream dos) throws IOException {
        dos.writeInt(0x646E450A);
        dos.writeInt(0);
    }
}
