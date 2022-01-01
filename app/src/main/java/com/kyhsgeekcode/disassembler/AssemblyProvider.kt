package com.kyhsgeekcode.disassembler

abstract class AssemblyProvider {
    abstract fun getAll(bytes: ByteArray, offset: Long, size: Long, virtaddr: Long): Long
    abstract fun getSome(
        bytes: ByteArray,
        offset: Long,
        size: Long,
        virtaddr: Long,
        count: Int
    ): List<DisassemblyListItem>
}