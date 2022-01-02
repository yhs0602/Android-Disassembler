package com.kyhsgeekcode.disassembler.Calc;

public class Data {
    long longVal;
    double doubleVal;
    String strVal;
    Type type;

    //String varName;
    public Data(long value) {
        longVal = value;
        type = Type.LONG;
    }

    public Data(double value) {
        doubleVal = value;
        type = Type.DOUBLE;
    }

    public Data(String value) {
        strVal = value;
        type = Type.STRING;
    }

    public long set(long value) {
        longVal = value;
        type = Type.LONG;
        return longVal;
    }

    public double set(double value) {
        doubleVal = value;
        type = Type.DOUBLE;
        return doubleVal;
    }

    public String set(String value) {
        strVal = value;
        type = Type.STRING;
        return strVal;
    }

    public Data set(Data data) {
        switch (data.type) {
            case LONG:
                this.longVal = data.longVal;
                break;
            case DOUBLE:
                this.doubleVal = data.doubleVal;
                break;
            case STRING:
                this.strVal = data.strVal;
        }
        return this;
    }

    public long getLong() {
        switch (type) {
            case LONG:
                return longVal;
            case DOUBLE:
                return (long) doubleVal;
            case STRING:
                return Long.parseLong(strVal);
        }
        return 0;
    }

    public double getDouble() {
        switch (type) {
            case LONG:
                return (double) longVal;
            case DOUBLE:
                return doubleVal;
            case STRING:
                return Double.parseDouble(strVal);
        }
        return 0;
    }

    public String getString() {
        switch (type) {
            case LONG:
                return "" + longVal;
            case DOUBLE:
                return "" + doubleVal;
            case STRING:
                return strVal;
        }
        return "";
    }

    @Override
    public String toString() {
        return getString();
    }

    enum Type {
        LONG,
        DOUBLE,
        STRING
    }
}
