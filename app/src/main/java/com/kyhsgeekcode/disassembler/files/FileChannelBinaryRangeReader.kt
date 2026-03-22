package com.kyhsgeekcode.disassembler.files

import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import kotlin.math.min

class FileChannelBinaryRangeReader(file: File) : BinaryRangeReader {
    private val channel = FileChannel.open(file.toPath(), StandardOpenOption.READ)

    override val size: Long
        get() = channel.size()

    override fun read(offset: Long, length: Int): ByteArray {
        require(offset >= 0) { "offset must be non-negative" }
        require(length >= 0) { "length must be non-negative" }
        if (length == 0 || offset >= size) {
            return ByteArray(0)
        }
        val readableLength = min(length.toLong(), size - offset).toInt()
        val buffer = ByteBuffer.allocate(readableLength)
        channel.read(buffer, offset)
        return buffer.array()
    }

    override fun readFully(): ByteArray {
        if (size == 0L) {
            return ByteArray(0)
        }
        require(size <= Int.MAX_VALUE) {
            "File is too large to fit into a ByteArray: $size bytes"
        }
        return read(offset = 0, length = size.toInt())
    }

    override fun close() {
        channel.close()
    }
}
