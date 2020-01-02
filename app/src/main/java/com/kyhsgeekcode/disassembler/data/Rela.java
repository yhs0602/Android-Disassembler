package com.kyhsgeekcode.disassembler.data;

import com.kyhsgeekcode.disassembler.data.Symbol;

public class Rela {
    public int targetSection;
    public int symsection;
    public long r_offset;
    public long r_info;
    public int index;
    public int type;
    public long r_addend;
    public Symbol symbol;
}
