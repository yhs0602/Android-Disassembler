package com.kyhsgeekcode.asminterpreter

import com.kyhsgeekcode.asminterpreter.instructions.Instruction

interface IAsmDataFeeder {
    fun getInstructionAt(address: Long): Instruction
    fun getDataAt(address: Long): ByteArray
}
