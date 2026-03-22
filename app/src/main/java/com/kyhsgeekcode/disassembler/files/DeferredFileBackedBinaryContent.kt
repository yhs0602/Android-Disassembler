package com.kyhsgeekcode.disassembler.files

import java.io.File

class DeferredFileBackedBinaryContent(
    private val file: File,
    initialContent: ByteArray? = null,
    private val loader: BinaryContentLoader? = null,
) {
    private var loadedContent: ByteArray? = initialContent

    fun contents(): ByteArray {
        val existing = loadedContent
        if (existing != null) {
            return existing
        }
        val loaded = loader?.load() ?: file.readBytes()
        loadedContent = loaded
        return loaded
    }

    fun length(): Long {
        return loadedContent?.size?.toLong() ?: file.length()
    }
}
