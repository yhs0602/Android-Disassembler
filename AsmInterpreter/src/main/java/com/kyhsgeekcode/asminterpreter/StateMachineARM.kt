package com.kyhsgeekcode.asminterpreter

import java.util.*


class StateMachineARM(val dataFeeder: IAsmDataFeeder) : IStateMachine {
    override var regs: MutableMap<Register, Long> = HashMap()
    override var flags: MutableMap<Flag, Boolean> = HashMap()
    override fun proceed() {
        val pc = regs[Register.PC]!!
        val intsruction = dataFeeder.getInstructionAt(pc)
        intsruction.execute(this)
//        val nextPc = pc + intsruction.size
//        regs.put(Register.PC, nextPc)
    }

}
