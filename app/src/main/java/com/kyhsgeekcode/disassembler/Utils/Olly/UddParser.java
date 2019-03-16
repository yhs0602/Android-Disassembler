package com.kyhsgeekcode.disassembler.Utils.Olly;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class UddParser {
    class Record
    {
        int magic; //32 bits
        int size; //32 bits
        public Record(ByteBuffer buf)
        {
            magic=buf.getInt();
            size=buf.getInt();
        }
        //little endian unsigned int

    }
    public static void ReadRecord(File file) throws IOException {
        int read=0;
        int index=0;
        int total=(int)file.length();
        byte[] bytes= new byte[total];
        InputStream is=new FileInputStream(file);
        while(is.available()>0)
        {
            read=is.read(bytes,index,4096);
            index+=read;
        }
        byte[] content=new byte[total];

    }
}
