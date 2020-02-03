package com.kyhsgeekcode.disassembler.Interpreter;

public abstract class Machine {
    long[] regs;

    public void Execute() {
    }

    public interface MachineCallback {

    }

    public class Instruction {
        byte[] bytes;
        int size;
        int id;
    }
}
