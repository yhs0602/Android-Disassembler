package com.kyhsgeekcode.disassembler.data

import android.app.Activity
import java.io.File
import java.io.IOException
import java.util.*

//Default project is created.
//ProjectNew instance is created when the user starts opening a zip or a apk or folder(?), or creates a project manually.
open class ProjectNew(private val activity: Activity) {
    var files: MutableMap<String, FileContext> = HashMap()
    var name: String? = null
    var path: String? = null
    @Throws(IOException::class)
    fun openFile(filePath: String) {
        val file = AbstractFile.createInstance(filePath)
        val fc = FileContext(activity, file)
        files[filePath] = fc
    }

    @Throws(IOException::class)
    fun openFile(file: File) {
        openFile(file.absolutePath)
    }

    //Called when no tab involving the file is open.
    fun closeFile(filePath: String?) {
        files.remove(filePath)
    }

}