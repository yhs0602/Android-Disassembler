package com.kyhsgeekcode.disassembler.files

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FileChannelBinaryRangeReaderTest {
    @Test
    fun readReturnsRequestedRange() {
        val file = createTempFileWithBytes(byteArrayOf(0x10, 0x11, 0x12, 0x13, 0x14))

        FileChannelBinaryRangeReader(file).use { reader ->
            assertContentEquals(byteArrayOf(0x11, 0x12, 0x13), reader.read(offset = 1, length = 3))
        }
    }

    @Test
    fun readClampsAtEndOfFile() {
        val file = createTempFileWithBytes(byteArrayOf(0x20, 0x21, 0x22))

        FileChannelBinaryRangeReader(file).use { reader ->
            assertContentEquals(byteArrayOf(0x21, 0x22), reader.read(offset = 1, length = 10))
        }
    }

    @Test
    fun readReturnsEmptyArrayPastEndOfFile() {
        val file = createTempFileWithBytes(byteArrayOf(0x30, 0x31))

        FileChannelBinaryRangeReader(file).use { reader ->
            assertTrue(reader.read(offset = 5, length = 4).isEmpty())
        }
    }

    @Test
    fun readFullyReturnsEntireFile() {
        val bytes = byteArrayOf(0x40, 0x41, 0x42, 0x43)
        val file = createTempFileWithBytes(bytes)

        FileChannelBinaryRangeReader(file).use { reader ->
            assertEquals(bytes.size.toLong(), reader.size)
            assertContentEquals(bytes, reader.readFully())
        }
    }

    private fun createTempFileWithBytes(bytes: ByteArray): File {
        return kotlin.io.path.createTempFile("range-reader", ".bin").toFile().apply {
            writeBytes(bytes)
            deleteOnExit()
        }
    }
}
