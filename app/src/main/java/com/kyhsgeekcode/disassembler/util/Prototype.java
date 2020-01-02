package com.kyhsgeekcode.disassembler.util;

import java.util.ArrayList;
import java.util.List;

public class Prototype {
    public String name;

    public class Parameter extends com.kyhsgeekcode.disassembler.util.Parameter {
        String type;
        String name;
    }

    public String returnType;
    public List<Parameter> params = new ArrayList<>();
}
