package com.kyhsgeekcode.disassembler

import at.pollaknet.api.facile.symtab.symbols.scopes.Assembly

// Normal disassembly and dotnet disassembly are different
// Address -> index of method or (address->method를 찾는 기능 만들기)
// size -> 1 or (실제 바이트 사이즈)
//
class DotNetAssemblyProvider(total: Long, var assembly: Assembly) : AssemblyProvider() {
    override fun getAll(bytes: ByteArray, offset: Long, size: Long, virtaddr: Long): Long {
        return 0
    }

    override fun getSome(
        bytes: ByteArray,
        offset: Long,
        size: Long,
        virtaddr: Long,
        count: Int
    ): List<DisassemblyListItem> {
        return listOf()
    }

    //Not implemented
    init {
        val types = assembly.allTypes
        for (t in types) {
            //t.get
        }
    }
}