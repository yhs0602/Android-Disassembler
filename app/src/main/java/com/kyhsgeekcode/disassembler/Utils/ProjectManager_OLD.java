package com.kyhsgeekcode.disassembler.Utils;

import android.util.Log;

import com.kyhsgeekcode.disassembler.Utils.Olly.UDDReader;
import com.kyhsgeekcode.disassembler.Utils.Olly.UddTag;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class ProjectManager_OLD {
    private static final String TAG = "Disasm PM_new";

    public static void Write() {

    }

    static Map<String, Class<?>> type2Reader = new HashMap<>();

    static {
        type2Reader.put("udd", UDDReader.class);
    }

    public static DisasmInfo Read(InputStream is, String type) throws IOException {
        try {
            return (DisasmInfo) type2Reader.get(type).getMethod("Read", InputStream.class).invoke(null, is);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            throw new IOException(e);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return new DisasmInfo();
    }

    public static DisasmInfo Read(File file) throws IOException {
        String name = file.getName();
        int li = name.lastIndexOf('.');
        String type = name.substring(li + 1);
        FileInputStream fis = new FileInputStream(file);
        return Read(fis, type);
    }


    //    static Map<UddTag, byte[]> uddData = new HashMap<>();

    public static Map<UddTag, byte[]> ReadUDD(DataInputStream is) throws IOException {
        Map<UddTag, byte[]> uddData = new HashMap<>();
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
        return uddData;
    }
}
