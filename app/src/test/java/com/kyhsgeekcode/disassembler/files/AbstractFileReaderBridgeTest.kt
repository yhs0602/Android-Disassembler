package com.kyhsgeekcode.disassembler.files

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class AbstractFileReaderBridgeTest {
    @Test
    fun `readFileContentsForParsing reads through range reader and closes it`() {
        val expected = byteArrayOf(1, 2, 3, 4)
        val fakeReader = FakeBinaryRangeReader(expected)

        val actual = AbstractFile.readFileContentsForParsing(createTempFileWithBytes(expected)) { fakeReader }

        assertContentEquals(expected, actual)
        assertTrue(fakeReader.closed)
        assertTrue(fakeReader.readFullyCalled)
    }

    private fun createTempFileWithBytes(bytes: ByteArray) =
        kotlin.io.path.createTempFile("abstract-file-reader", ".bin").toFile().apply {
            writeBytes(bytes)
            deleteOnExit()
        }

    private class FakeBinaryRangeReader(private val bytes: ByteArray) : BinaryRangeReader {
        var closed = false
        var readFullyCalled = false

        override val size: Long
            get() = bytes.size.toLong()

        override fun read(offset: Long, length: Int): ByteArray {
            throw UnsupportedOperationException("Not needed for this test")
        }

        override fun readFully(): ByteArray {
            readFullyCalled = true
            return bytes
        }

        override fun close() {
            closed = true
        }
    }
}
