package com.kyhsgeekcode.disassembler.utils

import android.util.Log
import com.kyhsgeekcode.TAG
import java.util.*

object NDKRefUrlMatcher {
    fun getURL(name: String): String? {
        if (name.startsWith("A")) {
            var index: Int? = null
            for (i in 2 until name.length) {
                if (Character.isUpperCase(name[i])) {
                    index = i
                    break
                }
            }
            if (index != null) {
                val module = name.substring(1, index).toLowerCase(Locale.ROOT)
                return "https://developer.android.com/ndk/reference/group/${module}#${
                    name.toLowerCase(
                        Locale.ROOT
                    )
                }"
            }
        } else {
            return "https://www.cplusplus.com/$name"
        }
        Log.e(TAG, "Failed to find url for $name")
        return null
    }
}