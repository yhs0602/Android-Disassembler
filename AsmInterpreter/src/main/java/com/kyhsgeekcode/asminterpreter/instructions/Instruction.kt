package com.kyhsgeekcode.asminterpreter.instructions

import com.kyhsgeekcode.asminterpreter.IStateController

interface Instruction {
    val size: Int
    fun execute(controllerI: IStateController)
}
