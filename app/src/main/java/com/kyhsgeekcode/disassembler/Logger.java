package com.kyhsgeekcode.disassembler;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Queue;

public class Logger {
    //private static Logger theInstance;
    private static Queue<LogData> data = new LinkedList<>();

    public static void v(String TAG, String desc) {
        log(TAG, desc, "Verbose");
        Log.v(TAG, desc);
    }

    public static void v(String TAG, String desc, Throwable e) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Verbose");
        Log.v(TAG, desc, e);
    }

    public static void e(String TAG, String desc) {
        log(TAG, desc, "Error");
        Log.e(TAG, desc);
    }

    public static void e(String TAG, String desc, Throwable e) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Error");
        Log.v(TAG, desc, e);
    }

    private static void log(String TAG, String desc, String level) {
        LogData ldata = new LogData();
        ldata.TAG = TAG;
        ldata.description = desc;
        ldata.time = SimpleDateFormat.getDateTimeInstance().format(new Date()); //new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        ldata.level = level;
        //Maximum 1023
        while (data.size() > 1024) {
            data.remove();
        }
        data.add(ldata);
    }

    public static Queue<LogData> getLogData() {
        return data;
    }
}
