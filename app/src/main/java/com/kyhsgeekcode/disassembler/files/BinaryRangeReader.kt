package com.kyhsgeekcode.disassembler.files

import java.io.Closeable

interface BinaryRangeReader : Closeable {
    val size: Long

    fun read(offset: Long, length: Int): ByteArray

    fun readFully(): ByteArray
}
