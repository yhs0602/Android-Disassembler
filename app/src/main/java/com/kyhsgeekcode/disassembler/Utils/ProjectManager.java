package com.kyhsgeekcode.disassembler.Utils;

import com.kyhsgeekcode.disassembler.MainActivity;

import java.io.DataInputStream;
import java.io.IOException;

public class ProjectManager {
    public static void Write() {

    }

    public static void Read(MainActivity a) {

    }

    static void ReadUDD(DataInputStream is) throws IOException {
        int type;
        int length;
        byte[] data;

        while (is.available() > 0) {
            type = is.readInt() & 0xFFffFFff;
            length = is.readInt() & 0xFFffFFff;
            data = new byte[length];
            is.read(data, 0, length);
            switch (type) {
                //case :
                //    break;
            }
        }
    }
}
