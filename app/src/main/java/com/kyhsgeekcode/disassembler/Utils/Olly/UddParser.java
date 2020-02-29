package com.kyhsgeekcode.disassembler.Utils.Olly;

//Deprecated!!!!!!!!!!!!!!!!!!!!!!!!!

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

//https://github.com/0vercl0k/stuffz/blob/master/ollydbg2-udd-files/udd.py seems not correct...?
//ex Sva/Sav, etc

public class UddParser {
    static Map<String, Method> dispatch_tale = new HashMap<>();

    static {
        try {
            dispatch_tale.put("\nJdt", UddParser.class.getMethod("handle_jdt_record"));

            dispatch_tale.put("\nMdt", UddParser.class.getMethod("handle_mdt_record"));

            dispatch_tale.put("\nSav", UddParser.class.getMethod("handle_sav_record"));

            dispatch_tale.put("\nPat", UddParser.class.getMethod("handle_pat_record"));

            dispatch_tale.put("\nCas", UddParser.class.getMethod("handle_cas_record"));

            dispatch_tale.put("\nBsv", UddParser.class.getMethod("handle_bsv_record"));

            dispatch_tale.put("\nDat", UddParser.class.getMethod("handle_dat_record"));

            dispatch_tale.put("\nFcr", UddParser.class.getMethod("handle_fcr_record"));

            dispatch_tale.put("\nCbr", UddParser.class.getMethod("handle_cbr_record"));

            dispatch_tale.put("\nLbr", UddParser.class.getMethod("handle_lbr_record"));

            dispatch_tale.put("\nBpm", UddParser.class.getMethod("handle_bpm_record"));

            dispatch_tale.put("\nBph", UddParser.class.getMethod("handle_bph_record"));

            dispatch_tale.put("\nPrd", UddParser.class.getMethod("handle_prd_record"));

            dispatch_tale.put("\nMne", UddParser.class.getMethod("handle_mne_record"));

            dispatch_tale.put("\nSwi", UddParser.class.getMethod("handle_swi_record"));

            dispatch_tale.put("\nWtc", UddParser.class.getMethod("handle_wtc_record"));

            dispatch_tale.put("\nPrc", UddParser.class.getMethod("handle_prc_record"));

            dispatch_tale.put("\nRtc", UddParser.class.getMethod("handle_rtc_record"));

            dispatch_tale.put("\nIn3", UddParser.class.getMethod("handle_in3_record"));

            dispatch_tale.put("\nMba", UddParser.class.getMethod("handle_mba_record"));

            dispatch_tale.put("\nAna", UddParser.class.getMethod("handle_ana_record"));

            dispatch_tale.put("\nLsa", UddParser.class.getMethod("handle_lsa_record"));

            dispatch_tale.put("\nEnd", UddParser.class.getMethod("handle_end_record"));
        } catch (NoSuchMethodException e) {

        }
    }

    private String HDR_MAGIC = "Mod\u0000";

    //public static void handle

    public static void ReadRecord(File file) throws IOException {
        int read = 0;
        int index = 0;
        int total = (int) file.length();
        byte[] bytes = new byte[total];
        InputStream is = new FileInputStream(file);
        while (is.available() > 0) {
            read = is.read(bytes, index, 4096);
            index += read;
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

    }

    class Record {
        int magic; //32 bits
        int size; //32 bits

        public Record(ByteBuffer buf) {
            magic = buf.getInt();
            size = buf.getInt();
            byte[] content = new byte[size];
            buf.get(content, 0, size);
            //struct.pack call
            //magic -> string
            char[] chs = new char[4];
            chs[0] = (char) ((magic >> 24) & 0xFF);
            chs[1] = (char) ((magic >> 16) & 0xFF);
            chs[2] = (char) ((magic >> 8) & 0xFF);
            chs[3] = (char) ((magic) & 0xFF);
            String s = new String(chs);
            try {
                dispatch_tale.get(s).invoke(null);
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            } catch (NullPointerException e) {

            } catch (Exception e) {

            }
        }
        //little endian unsigned int

    }

}
