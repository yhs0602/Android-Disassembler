package com.kyhsgeekcode.disassembler.Utils;

import android.util.Log;

import com.kyhsgeekcode.disassembler.MainActivity;
import com.kyhsgeekcode.disassembler.Utils.Olly.UddTag;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ProjectManager {
    private static final String TAG = "Disasm PM_new";
    public static void Write() {

    }

    public static void Read(MainActivity a) {

    }

    static Map<UddTag, byte[]> uddData = new HashMap<>();

    static void ReadUDD(DataInputStream is) throws IOException {
        int type;
        int length;
        byte[] data;
        uddData.clear();
        while (is.available() > 0) {
            type = is.readInt() & 0xFFffFFff;
            length = is.readInt() & 0xFFffFFff;
            data = new byte[length];
            is.read(data, 0, length);
            UddTag tag = UddTag.fromInt(type);
            if (tag == UddTag.TAG_UNKNOWN) {
                Log.w(TAG, "Unknown type:" + type);
            }
            uddData.put(tag, data);
        }
    }
}
