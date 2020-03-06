package com.kyhsgeekcode.disassembler.utils

import java.nio.ByteBuffer

// https://ekasiswanto.wordpress.com/2012/09/19/descriptions-of-androids-resources-arsc/
class DecompressResourceArsc {
    fun parse(data: ByteArray) {
        val buffer = ByteBuffer.wrap(data)
        while (buffer.hasRemaining()) {
            val chunkType = buffer.short
            when (chunkType.toInt()) {
                ResChunkHeader.RES_TABLE_TYPE -> {
                    val resTableHeader = ResTableHeader(ResChunkHeader(chunkType, buffer.short, buffer.int), buffer.int)
                }
                ResChunkHeader.RES_STRING_POOL_TYPE -> {
                    val stringPoolHeader = ResStringPoolHeader(ResChunkHeader(chunkType, buffer.short, buffer.int),
                            buffer.int, buffer.int, buffer.int, buffer.int, buffer.int)
                    for (i in 0 until stringPoolHeader.stringCount) {
                        val relval = buffer.int
                        val offset = stringPoolHeader.stringStart + relval
                        val strLen = (data[offset + 1] shl 8) + data[offset]
                        val str = String(data, offset + 2, offset + 2 + strLen)
                    }
                }
                ResChunkHeader.RES_TABLE_PACKAGE_TYPE -> {
                    val nameByteArray = ByteArray(128)
                    val resTablePackage = ResTablePackage(ResChunkHeader(chunkType, buffer.short, buffer.int),
                            buffer.int, buffer.get(nameByteArray).toString(), buffer.int, buffer.int, buffer.int, buffer.int)

                }
            }


        }

        /// res string pool header
    }

    class ResChunkHeader(val type: Short, val headerSize: Short, val size: Int) {
        companion object {
            val RES_STRING_POOL_TYPE = 1
            val RES_TABLE_TYPE: Int = 2
            val RES_TABLE_PACKAGE_TYPE = 0x0200
        }
    }

    class ResTableHeader(val header: ResChunkHeader, val packageCount: Int)
    class ResStringPoolHeader(val header: ResChunkHeader, val stringCount: Int, val styleCount: Int,
                              val flags: Int, val stringStart: Int, val styleStart: Int) {
        enum class Flag(val intValue: Int) {
            SORTED_FLAG(1 shl 0),
            UTF8_FLAG(1 shl 8)
        }
    }

    class ResTablePackage(val header: ResChunkHeader, val id: Int, val name: String, val typeStrings: Int,
                          val lastPublicType: Int, val keyStrings: Int, val lastPublicKey: Int)
}
