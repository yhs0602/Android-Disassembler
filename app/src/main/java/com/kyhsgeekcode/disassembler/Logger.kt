package com.kyhsgeekcode.disassembler

import android.util.Log
import timber.log.Timber
import java.text.SimpleDateFormat
import java.util.*

object Logger {
    //private static Logger theInstance;
    val logData: Queue<LogData> = LinkedList()
    fun v(TAG: String, desc: String) {
        log(TAG, desc, "Verbose")
        Timber.v(desc)
    }

    fun v(TAG: String, desc: String, e: Throwable?) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Verbose")
        Timber.v(e, desc)
    }

    fun e(TAG: String, desc: String) {
        log(TAG, desc, "Error")
        Timber.e(desc)
    }

    fun e(TAG: String, desc: String, e: Throwable?) {
        log(TAG, desc + System.lineSeparator() + Log.getStackTraceString(e), "Error")
        Timber.v(e, desc)
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