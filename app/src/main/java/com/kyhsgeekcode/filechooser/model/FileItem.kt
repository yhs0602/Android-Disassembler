package com.kyhsgeekcode.filechooser.model

import android.R
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Environment
import android.util.Log
import com.kyhsgeekcode.disassembler.GetAPKAsyncTask
import splitties.init.appCtx
import java.io.File
import java.util.*

open class FileItem {
    val TAG = "FileItem"

    constructor(text: String) {
        this.text = text
    }

    constructor(file: File) {
        this.text = file.name
        this.file = file
    }

    constructor(appInfo : ApplicationInfo) {
        this.applicationInfo = appInfo
    }

    var text: String = ""
    var file: File? = null
    var backFile: File? = null
    var applicationInfo : ApplicationInfo ?  = null
    fun canExpand(): Boolean {
        if (file?.isDirectory == true)
            return true
        return false
    }

    open fun listSubItems(publisher: (Int, Int) -> Unit = { _, _ -> }): List<FileItem> {
        if (!canExpand())
            return emptyList()

    }

    companion object {
        val rootItem = object : FileItem("Main") {
            override fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
                return listOf(fileRoot, fileSdcard, apps, processes)
            }
        }
        val fileRoot = FileItem(File("/"))
        val fileSdcard = FileItem(Environment.getExternalStorageDirectory())
        val apps = object : FileItem("Apps") {
            override fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
                val result = ArrayList<FileItem>()
                val pm: PackageManager = appCtx.packageManager
                //get a list of installed apps.
                val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                val numpkg = packages.size
                //dialog.setMessage("Sorting APKs...")
                publisher(numpkg * 2, 0)
                packages.sortBy {
                    pm.getApplicationLabel(it) as String
                }
                publisher(numpkg * 2, numpkg)
                var i = 0
                val defaultD: Drawable? = appCtx.getDrawable(R.drawable.gallery_thumb)
                for (packageInfo in packages) { //Log.d(TAG, "Installed package :" + packageInfo.packageName);
//Log.d(TAG, "Apk file path:" + packageInfo.sourceDir);
                    val applabel = pm.getApplicationLabel(packageInfo) as String
                    var icon: Drawable? = defaultD
                    try {
                        icon = pm.getApplicationIcon(packageInfo.packageName)
                    } catch (e: PackageManager.NameNotFoundException) {
                        Log.e(TAG, "", e)
                    }
                    val label = applabel + "(" + packageInfo.packageName + ")"
                    appList.add(FileItem(label, packageInfo.sourceDir, icon))
                    i++
                    if (i % 10 == 0) {
                        publisher(numpkg * 2, i + numpkg)
                    }
                }
            }
        }
    }

    val processes = object : FileItem("Processes") {
        override fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
            return listOf(FileItem("Currently unavailable"))
        }
    }
}

