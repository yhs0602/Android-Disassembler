package com.kyhsgeekcode.asminterpreter

interface IAsmDataFeeder {
    fun getInstructionAt(address: Long): Instruction
    fun getDataAt(address: Long): ByteArray
}
