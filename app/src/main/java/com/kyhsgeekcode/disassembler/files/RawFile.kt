package com.kyhsgeekcode.disassembler.files

import java.io.File

class RawFile(file: File, filecontent: ByteArray?) : AbstractFile() {
    init {
        fileContents = filecontent!!
        path = file.path
    }
}