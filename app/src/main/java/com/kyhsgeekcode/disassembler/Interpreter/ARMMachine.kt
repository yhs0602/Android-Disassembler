package com.kyhsgeekcode.disassembler.Interpreter

import capstone.Arm_const
import com.kyhsgeekcode.disassembler.DisasmResult

class ARMMachine {
    fun Execute(instruction: DisasmResult) {
        //instruction.
        when (instruction.id) {
            Arm_const.ARM_INS_ADC -> {

//                instruction.
            }
        }
        //ARMCommand cmd = cmdMap.get(instruction.id);
    } //private static final Map<Integer, ARMCommand> cmdMap = new HashMap<>();

    //static {
    //    cmdMap.
    //}
    // R0-R6
    // R7: syscall number
    // R8-R10
    // R11: Frame Pointer
    // R12: IP
    // R13: SP
    // R14: LR
    // R15: PC
    //       33222 22 2 2222 1111 111111 00000 00000
    //       10987 65 4 3210 9876 543210 98765 43210
    // CPSR: NZCVQ -- J _DNM __GE ____IT EAIFT ____M
    val CARRY = 29
    val regs = UIntArray(17)

    fun carry() = (regs[16] shr CARRY) and 1U

}