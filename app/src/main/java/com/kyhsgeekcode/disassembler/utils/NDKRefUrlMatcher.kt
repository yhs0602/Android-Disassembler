package com.kyhsgeekcode.disassembler.utils

import android.util.Log
import com.kyhsgeekcode.TAG
import java.util.*

object NDKRefUrlMatcher {
    fun getURL(name: String): String? {
        if (name.startsWith("A") || name.contains("android", true)) {
            var index: Int? = null
            for (i in 2 until name.length) {
                if (Character.isUpperCase(name[i])) {
                    index = i
                    break
                }
            }
            return if (index != null) {
                val module = name.substring(1, index).toLowerCase(Locale.ROOT)
                "https://developer.android.com/ndk/reference/group/${module}#${
                    name.lowercase(Locale.getDefault())
                }"
            } else {
                "https://developer.android.com/s/results?q=$name"
            }
        } else {
            return "https://www.cplusplus.com/$name"
        }
        Log.e(TAG, "Failed to find url for $name")
        return null
    }
}