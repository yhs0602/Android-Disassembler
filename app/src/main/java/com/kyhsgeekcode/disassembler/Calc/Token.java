package com.kyhsgeekcode.disassembler.Calc;

import java.util.HashMap;
import java.util.Map;

public class Token {
    public static final Map<String, Double> constants = new HashMap<>();

    static {
        constants.put("PI", Math.PI);
        constants.put("E", Math.E);
        constants.put("π", Math.PI);
    }

    Type type;
    String name;
    Data data;

    public Token(char[] src, int start, int n) {
        this(new String(src, start, n));
    }

    public Token(String s) {
        name = s;
        if (Character.isDigit(s.charAt(0))) {
            try {
                if (s.charAt(0) == '0' && (s.length() > 2) && (s.charAt(1) == 'x')) {
                    data = new Data(Long.parseLong(s.substring(2), 16));
                } else if (s.endsWith("b")) {
                    data = new Data(Long.parseLong(s.substring(0, s.length() - 1), 2));
                } else if (s.endsWith("h")) {
                    data = new Data(Long.parseLong(s.substring(0, s.length() - 1), 16));
                } else {
                    data = new Data(Double.parseDouble(s));
                }
            } catch (NumberFormatException e) {
                name = "Number with invalid format:" + name;
                data = new Data(0);
            }
        } else {
            //Var
            //name=s;
            if (constants.containsKey(name)) {
                data = new Data(constants.get(name));
            } else {
                data = new Data(0);
            }
        }

        type = Type.OPERAND;
    }

    public Token(String s, Type t) {
        name = s;
        type = t;
    }

    public Token(Data data) {
        this.data = data;
    }

    public boolean isOperator() {
        return type == Type.OPERATOR;
    }

    public boolean isOperand() {
        return type == Type.OPERAND;
    }

    public Data getValue() {
        return data;
    }

    @Override
    public String toString() {
        return "name=" + name + ",type=" + type + ",data=" + data;
    }

    enum Type {
        OPERATOR,
        OPERAND
    }

}
