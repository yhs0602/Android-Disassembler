package com.kyhsgeekcode.disassembler.data;

public class PLT {
    public String name;
    public long address;
    long value;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(name);
        sb.append(":").append(address).append("=").append(value);
        return sb.toString();
    }
}
