package com.kyhsgeekcode.disassembler.files

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class RawFileLazyContentTest {
    @Test
    fun `binaryLength uses file size before contents are loaded`() {
        val file = createTempFileWithBytes(byteArrayOf(1, 2, 3, 4, 5))

        val rawFile = RawFile(file, filecontent = null) { byteArrayOf(9, 9, 9) }

        assertEquals(5L, rawFile.getBinaryLength())
    }

    @Test
    fun `getBinaryContents loads deferred contents once`() {
        val file = createTempFileWithBytes(byteArrayOf(1, 2, 3))
        var loadCount = 0
        val rawFile = RawFile(file, filecontent = null) {
            loadCount++
            byteArrayOf(4, 5, 6)
        }

        assertContentEquals(byteArrayOf(4, 5, 6), rawFile.getBinaryContents())
        assertContentEquals(byteArrayOf(4, 5, 6), rawFile.getBinaryContents())
        assertEquals(1, loadCount)
        assertEquals(3L, rawFile.getBinaryLength())
    }

    private fun createTempFileWithBytes(bytes: ByteArray) =
        kotlin.io.path.createTempFile("raw-file", ".bin").toFile().apply {
            writeBytes(bytes)
            deleteOnExit()
        }
}
