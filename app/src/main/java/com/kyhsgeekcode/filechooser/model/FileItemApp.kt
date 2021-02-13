package com.kyhsgeekcode.filechooser.model

import android.graphics.drawable.Drawable
import com.kyhsgeekcode.Publisher
import com.kyhsgeekcode.disassembler.Logger
import com.kyhsgeekcode.extract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.apache.commons.io.FileUtils
import splitties.init.appCtx
import java.io.File

class FileItemApp(label: String, val realFile: File, val nativeFile: File, icon: Drawable?) :
    FileItem(label, realFile, icon) {
    //    override val TAG = FileItemApp::class.java.simpleName
    override suspend fun listSubItems(publisher: Publisher): List<FileItem> {
        getExpandedFile(appCtx.externalCacheDir ?: appCtx.cacheDir, realFile).also {
//            backFile = it
            if (!it.exists()) {
                extract(realFile, it) { count, total ->
                    publisher(count.toInt(), total.toInt())
                }
                if (nativeFile.exists()) {
                    if (nativeFile.canRead()) {
                        val targetFolder = it.resolve("libs")
                        val targetFile = targetFolder.resolve(nativeFile.name)
                        var madetargetFile = targetFile
                        var i = 0
                        while (targetFile.exists()) {
                            madetargetFile = File(targetFile.absolutePath + "_extractedLibs$i")
                            i++
                        }
                        targetFolder.mkdirs()
                        withContext(Dispatchers.IO) {
                            FileUtils.copyDirectory(nativeFile, madetargetFile)
                        }
                    } else {
                        Logger.e(TAG, "Native file $nativeFile could not be read")
                    }
                } else {
                    Logger.v(TAG, "Native file $nativeFile does not exist")
                }
            }
            return listSubItemsFile(it)
        }
    }

    override fun canExpand() = true
//    override fun cachedSubItems(): List<FileItem>? {
//        backFile = File(appCtx.cacheDir, realFile.name)
//        return if (backFile!!.exists()) {
//            listSubItemsFile(backFile!!)
//        } else null
//    }
}
