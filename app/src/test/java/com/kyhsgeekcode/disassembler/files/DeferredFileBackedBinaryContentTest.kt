package com.kyhsgeekcode.disassembler.files

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class DeferredFileBackedBinaryContentTest {
    @Test
    fun `contents returns initial content without invoking loader`() {
        var loadCount = 0
        val file = createTempFileWithBytes(byteArrayOf(1, 2, 3))
        val content = DeferredFileBackedBinaryContent(
            file = file,
            initialContent = byteArrayOf(4, 5, 6),
            loader = BinaryContentLoader {
                loadCount++
                byteArrayOf(7, 8, 9)
            }
        )

        assertContentEquals(byteArrayOf(4, 5, 6), content.contents())
        assertEquals(0, loadCount)
    }

    @Test
    fun `contents loads from loader only once when initial content is absent`() {
        var loadCount = 0
        val file = createTempFileWithBytes(byteArrayOf(1, 2, 3))
        val content = DeferredFileBackedBinaryContent(
            file = file,
            loader = BinaryContentLoader {
                loadCount++
                byteArrayOf(9, 8, 7)
            }
        )

        assertContentEquals(byteArrayOf(9, 8, 7), content.contents())
        assertContentEquals(byteArrayOf(9, 8, 7), content.contents())
        assertEquals(1, loadCount)
    }

    @Test
    fun `length uses file size before content is loaded`() {
        val file = createTempFileWithBytes(byteArrayOf(1, 2, 3, 4, 5))
        val content = DeferredFileBackedBinaryContent(file = file)

        assertEquals(5L, content.length())
    }

    private fun createTempFileWithBytes(bytes: ByteArray): File {
        return kotlin.io.path.createTempFile("deferred-content", ".bin").toFile().apply {
            writeBytes(bytes)
            deleteOnExit()
        }
    }
}
