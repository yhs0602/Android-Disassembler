package com.kyhsgeekcode.asminterpreter

import java.util.*

class StateMachine(val dataFeeder: IAsmDataFeeder) {
    var regs: MutableMap<Register, Long> = HashMap()
        private set

    fun proceed() {
        val pc = regs[Register.PC]!!
        val intsruction = dataFeeder.getInstructionAt(pc)



        val nextPc = pc + intsruction.size
        regs.put(Register.PC, nextPc)
    }
}
