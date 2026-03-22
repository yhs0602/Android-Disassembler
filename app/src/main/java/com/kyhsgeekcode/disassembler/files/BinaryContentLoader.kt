package com.kyhsgeekcode.disassembler.files

fun interface BinaryContentLoader {
    fun load(): ByteArray
}
