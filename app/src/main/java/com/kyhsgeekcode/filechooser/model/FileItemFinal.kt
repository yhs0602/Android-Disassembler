package com.kyhsgeekcode.filechooser.model

import android.graphics.drawable.Drawable

class FileItemFinal(text: String, drawable: Drawable? = null) : FileItem(text, drawable) {
    override fun isRawAvailable() = false
    override fun isAccessible(): Boolean = true
    override fun canExpand(): Boolean = false
    override fun isProjectAble(): Boolean = false
}
