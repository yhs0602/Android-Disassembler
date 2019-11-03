package com.kyhsgeekcode.disassembler;

public class PLT {
    String name;
    long address;
    long value;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(name);
        sb.append(":").append(address).append("=").append(value);
        return sb.toString();
    }
}
