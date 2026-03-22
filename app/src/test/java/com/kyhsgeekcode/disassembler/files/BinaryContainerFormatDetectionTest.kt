package com.kyhsgeekcode.disassembler.files

import kotlin.test.Test
import kotlin.test.assertEquals

class BinaryContainerFormatDetectionTest {
    @Test
    fun `detectBinaryContainerFormat recognizes ELF headers`() {
        val format = AbstractFile.detectBinaryContainerFormat(
            createTempFileWithBytes(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        ) { _ -> FakeHeaderReader(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())) }

        assertEquals(BinaryContainerFormat.ELF, format)
    }

    @Test
    fun `detectBinaryContainerFormat recognizes MZ headers as PE`() {
        val format = AbstractFile.detectBinaryContainerFormat(
            createTempFileWithBytes(byteArrayOf('M'.code.toByte(), 'Z'.code.toByte(), 0x00, 0x00))
        ) { _ -> FakeHeaderReader(byteArrayOf('M'.code.toByte(), 'Z'.code.toByte(), 0x00, 0x00)) }

        assertEquals(BinaryContainerFormat.PE, format)
    }

    @Test
    fun `detectBinaryContainerFormat falls back to RAW for unknown headers`() {
        val format = AbstractFile.detectBinaryContainerFormat(
            createTempFileWithBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03))
        ) { _ -> FakeHeaderReader(byteArrayOf(0x00, 0x01, 0x02, 0x03)) }

        assertEquals(BinaryContainerFormat.RAW, format)
    }

    private fun createTempFileWithBytes(bytes: ByteArray) =
        kotlin.io.path.createTempFile("binary-format", ".bin").toFile().apply {
            writeBytes(bytes)
            deleteOnExit()
        }

    private class FakeHeaderReader(private val header: ByteArray) : BinaryRangeReader {
        override val size: Long
            get() = header.size.toLong()

        override fun read(offset: Long, length: Int): ByteArray {
            return header.copyOf(minOf(length, header.size))
        }

        override fun readFully(): ByteArray = header

        override fun close() = Unit
    }
}
