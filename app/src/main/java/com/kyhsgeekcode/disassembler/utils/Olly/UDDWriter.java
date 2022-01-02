package com.kyhsgeekcode.disassembler.utils.Olly;

import com.kyhsgeekcode.disassembler.BuildConfig;
import com.kyhsgeekcode.disassembler.utils.CommentInfo;
import com.kyhsgeekcode.disassembler.utils.DisasmInfo;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class UDDWriter {
    public static final int GTAG_entryPoint = 0x55AA0001;
    public static final int GTAG_codeBase = 0x55AA0002;
    public static final int GTAG_codeLimit = 0x55AA0003;
    public static final int GTAG_codeVirtualAddress = 0x55AA0004;

    private static void WriteTag(DataOutputStream dos, int tag, int size, byte[] data) throws IOException {
        dos.writeInt(tag);
        dos.writeInt(size);
        dos.write(data);
    }

    private static void WriteSignature(DataOutputStream dos) throws IOException {
        try {
            byte[] bytes = "Module info file va1.7".getBytes(StandardCharsets.UTF_8);
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


    public static void WriteUDD(OutputStream os, DisasmInfo info) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        WriteSignature(dos);
        WriteVersion(dos);

        WriteTag(dos, 0x6C69460A, info.filepath);
        WriteTag(dos, 0x7A69530A, (int) info.filesize);     //Size
        WriteTagLong(dos, 0x7473540A, info.timestamp);    //Timestamp
        WriteTag(dos, 0x7263430A, 0);            //CRC
        WriteTagGeneral(dos, GTAG_entryPoint, info.entryPoint);                  //entry point
        WriteTagGeneral(dos, GTAG_codeBase, info.codeBase);                  //code base
        WriteTagGeneral(dos, GTAG_codeLimit, info.codeLimit);                  //code limit
        WriteTagGeneral(dos, GTAG_codeVirtualAddress, info.codeVirtualAddress);                  //virtual address
        for (CommentInfo ci : info.comments) {
            WriteTagComment(dos, 1987269898, ci.offset, ci.comment);
        }
        WriteFinish(dos);
        dos.close();
    }

    private static void WriteTagGeneral(DataOutputStream dos, int gtag, long longdata) throws IOException {
        dos.writeInt(0x6176530A);
        dos.writeInt(12);
        dos.writeInt(gtag);
        dos.writeLong(longdata);
    }

    private static void WriteTagComment(DataOutputStream dos, int tag, long offset, String comment) throws IOException {
        dos.writeInt(tag);
        byte[] bytes = comment.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(bytes.length + 4);
        dos.writeInt((int) offset);
        dos.write(bytes);
    }

    private static void WriteVersion(DataOutputStream dos) throws IOException {
        dos.writeInt(0x7265560A);
        dos.writeInt(16);
        dos.writeInt(0);
        dos.writeInt(0);
        dos.writeInt(0);
        dos.writeInt(BuildConfig.VERSION_CODE);
    }

    private static void WriteTag(DataOutputStream dos, int tag, String data) throws IOException {
        try {
            byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
            WriteTag(dos, tag, bytes.length, bytes);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static void WriteTag(DataOutputStream dos, int tag, int data) throws IOException {
        dos.writeInt(tag);
        dos.writeInt(4);
        dos.writeInt(data);
    }

    private static void WriteTagLong(DataOutputStream dos, int tag, long data) throws IOException {
        dos.writeInt(tag);
        dos.writeInt(8);
        dos.writeLong(data);
    }

}
