package com.kyhsgeekcode.disassembler.files

import java.io.File

class RawFile(
    file: File,
    filecontent: ByteArray?,
    private val deferredContentLoader: (() -> ByteArray)? = null
) : AbstractFile() {
    private var contentLoaded = filecontent != null
    private val binaryContent = DeferredFileBackedBinaryContent(
        file = file,
        initialContent = filecontent,
        loader = deferredContentLoader?.let { BinaryContentLoader { it() } },
    )

    init {
        path = file.path
    }

    override fun getBinaryContents(): ByteArray {
        if (!contentLoaded) {
            fileContents = binaryContent.contents()
            contentLoaded = true
        }
        return fileContents
    }

    override fun getBinaryLength(): Long {
        return if (contentLoaded) fileContents.size.toLong() else binaryContent.length()
    }
}
