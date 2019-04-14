package com.kyhsgeekcode.disassembler;

public class Rela {
    int targetSection;
    int symsection;
    long r_offset;
    long r_info;
    int index;
    int type;
    long r_addend;
    Symbol symbol;
}
