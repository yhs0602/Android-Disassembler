package com.kyhsgeekcode.disassembler.Utils;

import java.util.ArrayList;
import java.util.List;

public class Prototype {
    public String name;
    public class Parameter
    {
        String type;
        String name;
    }
    public String returnType;
    public List<Parameter> params=new ArrayList<>();
}
