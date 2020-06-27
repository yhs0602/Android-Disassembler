package com.kyhsgeekcode

import java.util.*

object FileExtensions {
    val textFileExts: MutableSet<String> = HashSet()

    init {
        textFileExts.add("xml")
        textFileExts.add("txt")
        textFileExts.add("smali")
        textFileExts.add("java")
        textFileExts.add("json")
        textFileExts.add("md")
        textFileExts.add("il")
        textFileExts.add("properties")
    }

    val peFileExts: MutableSet<String> = HashSet()

    init {
        peFileExts.add("acm")
        peFileExts.add("ax")
        peFileExts.add("cpl")
        peFileExts.add("dll")
        peFileExts.add("drv")
        peFileExts.add("efi")
        peFileExts.add("exe")
        peFileExts.add("mui")
        peFileExts.add("ocx")
        peFileExts.add("scr")
        peFileExts.add("sys")
        peFileExts.add("tsp")
    }
}
