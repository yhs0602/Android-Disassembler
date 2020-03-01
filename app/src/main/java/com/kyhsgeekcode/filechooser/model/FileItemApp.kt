package com.kyhsgeekcode.filechooser.model

import android.graphics.drawable.Drawable
import com.kyhsgeekcode.extract
import java.io.File
import splitties.init.appCtx

class FileItemApp(label: String, val realFile: File, icon: Drawable?) : FileItem(label, realFile, icon) {
    override fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
        backFile = File(appCtx.cacheDir, realFile.name)
        extract(realFile, backFile!!) { total, count ->
            publisher(total.toInt(), count.toInt())
        }
        return listSubItemsFile(backFile!!)
    }

    override fun canExpand() = true
}
