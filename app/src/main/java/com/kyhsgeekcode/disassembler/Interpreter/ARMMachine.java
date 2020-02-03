package com.kyhsgeekcode.disassembler.Interpreter;

import com.kyhsgeekcode.disassembler.data.DisasmResult;

import capstone.Arm_const;

public class ARMMachine {
    public void Execute(DisasmResult instruction) {
        //instruction.
        switch (instruction.getId()) {
            case Arm_const.ARM_INS_ADC:

        }
        //ARMCommand cmd = cmdMap.get(instruction.id);
    }
    //private static final Map<Integer, ARMCommand> cmdMap = new HashMap<>();
    //static {
    //    cmdMap.
    //}
}