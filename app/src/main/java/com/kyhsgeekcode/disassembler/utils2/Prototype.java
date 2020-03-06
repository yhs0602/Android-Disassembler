package com.kyhsgeekcode.disassembler.utils2;

import java.util.ArrayList;
import java.util.List;

public class Prototype {
    public String name;
    public String returnType;
    public List<Parameter> params = new ArrayList<>();

    public class Parameter extends com.kyhsgeekcode.disassembler.utils2.Parameter {
        String type;
        String name;
    }
}
