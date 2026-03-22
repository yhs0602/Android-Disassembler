package com.kyhsgeekcode.disassembler.files

import java.io.File

class RawFile(
    private val file: File,
    filecontent: ByteArray?,
    private val deferredContentLoader: (() -> ByteArray)? = null
) : AbstractFile() {
    private var contentLoaded = false

    init {
        if (filecontent != null) {
            fileContents = filecontent
            contentLoaded = true
        }
        path = file.path
    }

    override fun getBinaryContents(): ByteArray {
        if (!contentLoaded) {
            fileContents = deferredContentLoader?.invoke()
                ?: throw IllegalStateException("No file contents available for raw binary")
            contentLoaded = true
        }
        return fileContents
    }

    override fun getBinaryLength(): Long {
        return if (contentLoaded) {
            fileContents.size.toLong()
        } else {
            file.length()
        }
    }
}
