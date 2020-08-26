package com.kyhsgeekcode.asminterpreter.instructions

import com.kyhsgeekcode.asminterpreter.IStateController
import com.kyhsgeekcode.asminterpreter.Register

class Mov(
        override val size: Int,
        val from: Register,
        val to: Register
) : Instruction {
    override fun execute(controllerI: IStateController) {
        controllerI.regs[to] = controllerI.regs[from]!!
    }
}
