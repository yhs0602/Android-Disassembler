package com.kyhsgeekcode.asminterpreter

interface IStateController {
    var regs: MutableMap<Register, Long>
    var flags: MutableMap<Flag, Boolean>

}
