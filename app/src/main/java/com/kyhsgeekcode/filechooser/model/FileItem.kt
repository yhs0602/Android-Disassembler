package com.kyhsgeekcode.filechooser.model

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Environment
import android.util.Log
import androidx.core.content.ContextCompat
import at.pollaknet.api.facile.Facile
import com.kyhsgeekcode.*
import com.kyhsgeekcode.disassembler.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import splitties.init.appCtx
import java.io.File
import java.io.Serializable

// A item of base, or a file
open class FileItem : Serializable {
    val TAG = "FileItem"

    constructor(text: String, drawable: Drawable? = null) {
        this.text = text
        this.drawable = drawable
    }

    constructor(text: String? = null, file: File, drawable: Drawable? = null) {
        this.text = text ?: file.name + if (file.isDirectory) "/" else ""
        this.file = file
        this.drawable = drawable ?: getAppropriateDrawable()
    }

    private fun getAppropriateDrawable(): Drawable? {
        var id: Int = R.drawable.ic_file
        if (file?.isDexFile() == true) {
            id = R.drawable.ic_dex
        }
        if (file?.isDirectory == true) {
            id = R.drawable.ic_folder_icon
        }
        if (file?.isArchive() == true) {
            id = R.drawable.zip
        }
        if (file?.isDotnetFile() == true) {
            id = R.drawable.ic_dotnet
        }
        return ContextCompat.getDrawable(appCtx, id)
    }

    var text: String = ""

    @Transient
    var drawable: Drawable? = null

    var file: File? = null // 항목이 의미하는 파일 자체
//    protected var backFile: File? = null // 항목이 전개되었을 때 나타낼 디렉토리

    private val isExpandable: Boolean by lazy {
        file?.isDirectory == true ||
                file?.isArchive() == true ||
                file == null ||
                file?.isDotnetFile() == true ||
                file?.isDexFile() == true
    }

    open fun canExpand(): Boolean {
        return isExpandable && isAccessible()
    }

    open fun isRawAvailable(): Boolean = file?.isDirectory == false

    open fun isAccessible(): Boolean = file?.isAccessible() ?: true

    open fun isProjectAble(): Boolean = file?.isDirectory == true

    open suspend fun listSubItems(publisher: (current: Int, total: Int) -> Unit = { _, _ -> }): List<FileItem> {
        if (!canExpand())
            return emptyList()
        file?.run run1@{ ->
            when {
                isDirectory -> {
                    return listSubItemsFile(this, publisher)
                }
                isArchive() -> {
                    getExpandedFile(appCtx.externalCacheDir ?: appCtx.cacheDir, this)
                        .also {
//                            backFile = it
                            if (!it.exists()) {
                                try {
                                    extract(this@run1, it) { current, total ->
                                        publisher(
                                            current.toInt(),
                                            total.toInt()
                                        )
                                    }
                                } catch (e: Exception) {
                                    val result = listSubItemsFile(it) as MutableList
                                    result.add(FileItem("Exception ${e.message}"))
                                    return result
                                }
                            }
                            return listSubItemsFile(it, publisher)
                        }
                }
                isDexFile() -> {
                    getExpandedFile(appCtx.externalCacheDir ?: appCtx.cacheDir, this)
                        .also {
//                            backFile = it
                            publisher(3, 10)
                            if (!it.exists()) {
                                withContext(Dispatchers.IO) {
                                    org.jf.baksmali.Main.main(
                                        arrayOf(
                                            "d",
                                            "-o",
                                            it.absolutePath,
                                            this@run1.path
                                        )
                                    )
                                }
                            }
                            publisher(9, 10)
                            return listSubItemsFile(it, publisher)
                        }
                }
                isDotnetFile() -> {
                    val result = ArrayList<FileItem>()
                    publisher(1, 10)
                    val facileReflector = withContext(Dispatchers.IO) {
                        Facile.load(this@run1.path)
                    }
                    publisher(9, 10)
                    // load the assembly
                    // load the assembly
                    val assembly = facileReflector.loadAssembly()
                    val types = assembly.allTypes
                    for (type in types) {
                        result.add(
                            FileItemDotNetSymbol(
                                type.namespace + "." + type.name,
                                facileReflector,
                                type
                            )
                        )
                    }
                    publisher(10, 10)
                    return result
                }
                else -> return emptyList()
            }

        }
        return emptyList()
    }

    fun listSubItemsFile(
        parent: File,
        publisher: (current: Int, total: Int) -> Unit = { _, _ -> }
    ): List<FileItem> {
        val result = ArrayList<FileItem>()
        parent.listFiles()?.run {
            val total = size
            withIndex().forEach {
                result.add(FileItem(file = it.value))
                publisher(it.index + 1, total)
            }
        }
        return result
    }

//    open suspend fun cachedSubItems(): List<FileItem>? {
//        file?.run {
//            when {
//                isDirectory -> {
//                    return null
//                }
//                isArchive() -> {
//                    val result = ArrayList<FileItem>()
//                    backFile = getExpandedFile(appCtx.externalCacheDir ?: appCtx.cacheDir, this)
//                    // ?: appCtx.getExternalFilesDir("extracted")?.resolve(name)
//                    return if (backFile?.exists() == true) {
//                        backFile?.listFiles()?.forEach {
//                            result.add(FileItem(file = it))
//                        }
//                        result
//                    } else null
//                }
//                isDexFile() -> {
//                    val result = ArrayList<FileItem>()
//                    backFile = appCtx.getExternalFilesDir("dex-decompiled")?.resolve(name)
//                    return if (backFile?.exists() == true) {
//                        backFile?.listFiles()?.forEach {
//                            result.add(FileItem(file = it))
//                        }
//                        result
//                    } else null
//                }
//                isDotnetFile() -> {
//                    return null
//                }
//                else -> return null
//            }
//        }
//        return null
//    }

    companion object {
        val rootItem = object : FileItem("Main") {
            override suspend fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
                return listOf(fileRoot, fileSdcard, apps, processes, others, zoo, hash)
            }

            override fun canExpand(): Boolean = true
            override fun isRawAvailable(): Boolean = false
            override fun isProjectAble(): Boolean = false
        }

        val fileRoot = FileItem(file = File("/"))

        val fileSdcard = FileItem(file = Environment.getExternalStorageDirectory())

        val apps = object : FileItem("Apps", getDrawable(android.R.drawable.sym_def_app_icon)) {
            override fun canExpand(): Boolean = true
            override fun isRawAvailable(): Boolean = false
            override fun isProjectAble(): Boolean = false
            override suspend fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> =
                withContext(Dispatchers.IO) {
                    val result = ArrayList<FileItem>()
                    val pm: PackageManager = appCtx.packageManager
                    // get a list of installed apps.
                    val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    val numpkg = packages.size
                    // dialog.setMessage("Sorting APKs...")
                    publisher(0, numpkg * 2)
                    packages.sortBy {
                        pm.getApplicationLabel(it) as String
                    }
                    publisher(numpkg, numpkg * 2)
                    var i = 0
                    val defaultD: Drawable? = getDrawable(android.R.drawable.gallery_thumb)
                    for (packageInfo in packages) { // Log.d(TAG, "Installed package :" + packageInfo.packageName);
// Log.d(TAG, "Apk file path:" + packageInfo.sourceDir);
                        val applabel = pm.getApplicationLabel(packageInfo) as String
                        var icon: Drawable? = defaultD
                        try {
                            icon = pm.getApplicationIcon(packageInfo.packageName)
                        } catch (e: PackageManager.NameNotFoundException) {
                            Log.e(TAG, "", e)
                        }
                        val label = applabel + "(" + packageInfo.packageName + ")"
                        result.add(
                            FileItemApp(
                                label,
                                File(packageInfo.sourceDir),
                                File(packageInfo.nativeLibraryDir),
                                icon
                            )
                        )
                        i++
                        if (i % 10 == 0) {
                            publisher(i + numpkg, numpkg * 2)
                        }
                    }
                    result
                }
        }

        val processes = object : FileItem("Processes", getDrawable(R.drawable.fileitem_processes)) {
            override suspend fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
                return listOf(FileItem("Currently unavailable"))
            }

            override fun isRawAvailable(): Boolean = false
            override fun isProjectAble(): Boolean = false
        }

        val others =
            object : FileItem("Other sources", getDrawable(R.drawable.fileitem_etc_google_drive)) {
                override fun canExpand(): Boolean = false
                override fun isRawAvailable(): Boolean = true
                override fun isProjectAble(): Boolean = false
            }

        val zoo = object :
            FileItem("LIVE malware Zoo", getDrawable(R.drawable.fileitem_zoo_github_mark)) {
            override fun canExpand(): Boolean = false
            override fun isRawAvailable(): Boolean = true
            override fun isProjectAble(): Boolean = false
        }

        val hash = object : FileItem(
            "Malware sample by hash from infosec",
            getDrawable(R.drawable.fileitem_hash_icons8_website)
        ) {
            override fun canExpand(): Boolean = false
            override fun isRawAvailable(): Boolean = true
            override fun isProjectAble(): Boolean = false
        }
    }
}
