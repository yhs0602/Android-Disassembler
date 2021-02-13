package com.kyhsgeekcode.disassembler

import android.util.Log
import java.text.SimpleDateFormat
import java.util.*

object Logger {
    //private static Logger theInstance;
    val logData: Queue<LogData> = LinkedList()
    fun v(TAG: String, desc: String) {
        log(TAG, desc, "Verbose")
        Log.v(TAG, desc)
    }

    fun v(TAG: String, desc: String, e: Throwable?) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Verbose")
        Log.v(TAG, desc, e)
    }

    fun e(TAG: String, desc: String) {
        log(TAG, desc, "Error")
        Log.e(TAG, desc)
    }

    fun e(TAG: String, desc: String, e: Throwable?) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Error")
        Log.v(TAG, desc, e)
    }

    private fun log(TAG: String, desc: String, level: String) {
        val ldata = LogData(
            TAG,
            desc,
            SimpleDateFormat.getDateTimeInstance().format(Date()),
            //new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
            level
        )
        //Maximum 1023
        while (logData.size > 1024) {
            logData.remove()
        }
        logData.add(ldata)
    }
}