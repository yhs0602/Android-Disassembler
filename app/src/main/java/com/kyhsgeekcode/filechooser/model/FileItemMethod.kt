package com.kyhsgeekcode.filechooser.model

import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.symtab.symbols.Method

class FileItemMethod(text: String, reflector: FacileReflector, method: Method) : FileItem(text) {
    override fun canExpand(): Boolean = false
    override fun isAccessible(): Boolean = true
    override fun isRawAvailable(): Boolean = true
}
