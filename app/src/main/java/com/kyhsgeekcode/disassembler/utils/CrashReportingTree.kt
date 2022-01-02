package com.kyhsgeekcode.disassembler.utils

import android.util.Log
import com.google.firebase.crashlytics.FirebaseCrashlytics
import timber.log.Timber

class CrashReportingTree : Timber.Tree() {
    val crashlytics = FirebaseCrashlytics.getInstance()

    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (priority == Log.VERBOSE || priority == Log.DEBUG) {
            return
        }
        crashlytics.log(message)
        if (t != null) {
            if (priority == Log.ERROR) {
                crashlytics.recordException(t)
            } else if (priority == Log.WARN) {
                crashlytics.recordException(t)
            }
        }
    }
}
