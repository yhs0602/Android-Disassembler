package com.kyhsgeekcode.disassembler.Calc;

//unary operator:??

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

public class Operator extends Token implements Comparable<Operator> {

    static final Map<Character, Operation> ch2op = new HashMap<>();
    static final Map<String, Operation> str2op = new HashMap<>();
    static final List<String> keyList = new ArrayList<>();
    private static final Map<Operation, Integer> op2priority = new HashMap<>();

    static {
        ch2op.put('+', Operation.ADD);
        ch2op.put('-', Operation.SUB);
        ch2op.put('*', Operation.MULT);
        ch2op.put('×', Operation.MULT);
        ch2op.put('÷', Operation.DIV);
        ch2op.put('/', Operation.DIV);
        ch2op.put('=', Operation.MOV);
        ch2op.put('(', Operation.LPAR);
        ch2op.put(')', Operation.RPAR);

    }

    static {
        str2op.put(">>", Operation.SHR);
        str2op.put("<<", Operation.SHL);
        str2op.put(">>>", Operation.ASHR);
        str2op.put("<<<", Operation./*A*/SHL);
        str2op.put("<<<<", Operation.ROL);
        str2op.put(">>>>", Operation.ROR);
        str2op.put("**", Operation.POWER);
        str2op.put("++", Operation.PINC);
        str2op.put("--", Operation.PDEC);

        str2op.put("sin", Operation.SIN);
        str2op.put("cos", Operation.COS);
        str2op.put("exp", Operation.EXP);
        str2op.put("ln", Operation.LN);
        str2op.put("log2", Operation.LOG2);
        str2op.put("tan", Operation.TAN)
        ;
        str2op.put("sinh", Operation.SINH);
        str2op.put("cosh", Operation.COSH);
        str2op.put("tanh", Operation.TANH);
        str2op.put("asin", Operation.ASIN);
        str2op.put("acos", Operation.ACOS);
        str2op.put("atan", Operation.ATAN);
        str2op.put("sec", Operation.SEC);
        str2op.put("csc", Operation.CSC);
        str2op.put("cot", Operation.COT);
        str2op.put("cosec", Operation.CSC);


        str2op.put("hex", Operation.HEX);
        str2op.put("bin", Operation.BIN);
        str2op.put("oct", Operation.OCT);
        str2op.put("dec", Operation.DEC);
        str2op.put("polar", Operation.POLAR);

        str2op.put("sqrt", Operation.SQRT);
        str2op.put("√", Operation.SQRT);
        //str2op.put("*",Operation.MULT);
        //str2op.put('/',Operation.DIV);
        //str2op.put('=',Operation.MOV);
        Set<String> ks = str2op.keySet();
        keyList.addAll(ks);
        Collections.sort(keyList, (p1, p2) -> p2.length() - p1.length());
    }

    static {
        op2priority.put(Operation.SINC, 1);
        op2priority.put(Operation.SDEC, 1);
        op2priority.put(Operation.LPAR, 1);
        op2priority.put(Operation.RPAR, 1);
        op2priority.put(Operation.MEMB, 1);
        op2priority.put(Operation.MEMP, 1);
        op2priority.put(Operation.LSUB, 1);
        op2priority.put(Operation.RSUB, 1);

        op2priority.put(Operation.PINC, 2);
        op2priority.put(Operation.PDEC, 2);
        op2priority.put(Operation.UPLUS, 2);
        op2priority.put(Operation.UMINUS, 2);
        op2priority.put(Operation.LNOT, 2);
        op2priority.put(Operation.BNOT, 2);
        op2priority.put(Operation.CAST, 2);
        op2priority.put(Operation.DREF, 2);
        op2priority.put(Operation.ADDR, 2);
        op2priority.put(Operation.SIZEOF, 2);
        op2priority.put(Operation.ALIGNOF, 2);

        op2priority.put(Operation.MULT, 3);
        op2priority.put(Operation.DIV, 3);
        op2priority.put(Operation.REMAINDER, 3);

        op2priority.put(Operation.ADD, 4);
        op2priority.put(Operation.SUB, 4);

        op2priority.put(Operation.SHR, 5);
        op2priority.put(Operation.SHL, 5);

        op2priority.put(Operation.GT, 6);
        op2priority.put(Operation.LT, 6);
        op2priority.put(Operation.GE, 6);
        op2priority.put(Operation.LE, 6);

        op2priority.put(Operation.NE, 7);
        op2priority.put(Operation.EQ, 7);

        op2priority.put(Operation.BAND, 8);
        op2priority.put(Operation.BXOR, 9);
        op2priority.put(Operation.BOR, 10);

        op2priority.put(Operation.LAND, 11);
        op2priority.put(Operation.LOR, 12);

        op2priority.put(Operation.TEN, 13);

        op2priority.put(Operation.MOV, 14);
        op2priority.put(Operation.MOVADD, 14);
        op2priority.put(Operation.MOVSUB, 14);
        op2priority.put(Operation.MOVMUL, 14);
        op2priority.put(Operation.MOVDIV, 14);
        op2priority.put(Operation.MOVREM, 14);
        op2priority.put(Operation.MOVSHR, 14);
        op2priority.put(Operation.MOVSHL, 14);
        op2priority.put(Operation.MOVROR, 14);
        op2priority.put(Operation.MOVROL, 14);
        op2priority.put(Operation.MOVAND, 14);
        op2priority.put(Operation.MOVXOR, 14);
        op2priority.put(Operation.MOVOR, 14);

        op2priority.put(Operation.COMMA, 15);
        op2priority.put(Operation.SEMICOLON, 15);
    }

    Operation operation;

    //public double
    Operator(String s) {
        super(s, Type.OPERATOR);
        if (operation == null) {
            operation = str2op.get(s);
        }
        if (operation == null)
            operation = Operation.MULT;
    }

    Operator(char c) {
        this("" + c);
        operation = ch2op.get(c);
        if (operation == null)
            operation = Operation.MULT;
    }

    public Operator(char[] src, int start, int n) {
        this(new String(src, start, n));
        //type=Type.OPERATOR;
    }

    //returns positive if this is higher
    @Override
    public int compareTo(Operator p1) {
        Integer myp = op2priority.get(this.operation);
        Integer youp = op2priority.get(p1.operation);
        if (myp == null && youp == null)
            return 0;
        if (myp == null)
            return -1;
        if (youp == null)
            return -1;
        return -myp.compareTo(youp);
    }

    Data calc(Stack<Token> stack) {
        switch (operation) {
            case ADD:
                return new Data(stack.pop().getValue().getDouble() + stack.pop().getValue().getDouble());
            case SUB:
                return new Data(-(stack.pop().getValue().getDouble()) + stack.pop().getValue().getDouble());
            case MOV: {
                Data data1 = stack.pop().getValue();
                Data dataDest = stack.pop().getValue();
                return dataDest.set(data1);
            }
            case MULT: {
                return new Data(stack.pop().getValue().getDouble() * stack.pop().getValue().getDouble());
            }
            case DIV: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getDouble() / data1.getDouble());
            }
            case REMAINDER: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getDouble() % data1.getDouble());
            }
            case POWER: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(Math.pow(data2.getDouble(), data1.getDouble()));
            }
            case SHR: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getLong() >> data1.getLong());
            }
            case SHL: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getLong() << data1.getLong());
            }
            case ASHR: {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getLong() >>> data1.getLong());
            }
            case ASHL://Dummy
            {
                Data data1 = stack.pop().getValue();
                Data data2 = stack.pop().getValue();
                return new Data(data2.getLong() << data1.getLong());
            }
            case BAND: {
                return new Data(stack.pop().getValue().getLong() & stack.pop().getValue().getLong());
            }
            case BXOR: {
                return new Data(stack.pop().getValue().getLong() ^ stack.pop().getValue().getLong());
            }
            case BOR: {
                return new Data(stack.pop().getValue().getLong() | stack.pop().getValue().getLong());
            }
            case LOR: {
                return new Data((stack.pop().getValue().getLong() | stack.pop().getValue().getLong()) != 0 ? 1 : 0);
            }
            case LAND: {
                return new Data((stack.pop().getValue().getLong() & stack.pop().getValue().getLong()) != 0 ? 1 : 0);
            }
            case LNOT: {
                return new Data((stack.pop().getValue().getLong()) != 0 ? 0 : 1);
            }
            case BNOT: {
                return new Data(~stack.pop().getValue().getLong());
            }
            case EQ: {
                return new Data(stack.pop().getValue().equals(stack.pop().getValue()) ? 1 : 0);
            }
            case NE: {
                return new Data(stack.pop().getValue().equals(stack.pop().getValue()) ? 0 : 1);
            }
            case SIN: {
                return new Data(Math.sin(stack.pop().getValue().getDouble()));
            }
            case COS: {
                return new Data(Math.cos(stack.pop().getValue().getDouble()));
            }
            case TAN: {
                return new Data(Math.tan(stack.pop().getValue().getDouble()));
            }
            case ASIN: {
                return new Data(Math.asin(stack.pop().getValue().getDouble()));
            }
            case ACOS: {
                return new Data(Math.acos(stack.pop().getValue().getDouble()));
            }
            case ATAN: {
                return new Data(Math.atan(stack.pop().getValue().getDouble()));
            }
            case CSC: {
                return new Data(1.0 / Math.sin(stack.pop().getValue().getDouble()));
            }
            case SEC: {
                return new Data(1.0 / Math.cos(stack.pop().getValue().getDouble()));
            }
            case COT: {
                return new Data(1.0 / Math.tan(stack.pop().getValue().getDouble()));
            }
            case EXP: {
                return new Data(Math.exp(stack.pop().getValue().getDouble()));
            }
            case LN: {
                return new Data(Math.log(stack.pop().getValue().getDouble()));
            }
            case LOG2: {
                return new Data(Math.log(stack.pop().getValue().getDouble()) / Math.log(2));
            }
            case SINH: {
                return new Data(Math.sinh(stack.pop().getValue().getDouble()));
            }
            case COSH: {
                return new Data(Math.cosh(stack.pop().getValue().getDouble()));
            }
            case TANH: {
                return new Data(Math.tanh(stack.pop().getValue().getDouble()));
            }
            case HEX: {
                return new Data(Long.toHexString(stack.pop().getValue().getLong()));
            }
            case OCT: {
                return new Data(Long.toOctalString(stack.pop().getValue().getLong()));
            }
            case BIN: {
                return new Data(Long.toBinaryString(stack.pop().getValue().getLong()));
            }
            case DEC: {
                return new Data(stack.pop().getValue().getString());
            }
            case POLAR: {
                return new Data(Math.sin(stack.pop().getValue().getDouble()));
            }

        }
        return null;
    }

    enum Operation {
        //order by priority
        //PLUS,
        //MINUS,
        MULT,
        DIV,
        SHR,
        SHL,
        ROR,
        ROL,
        ASHR,
        ASHL,
        POWER,
        MOV,
        SEDC,
        SINC,
        PINC,
        PDEC,
        LPAR,
        RPAR,
        LBLK,
        RBLK,
        LSUB,
        RSUB,
        SDEC,
        MEMB,
        MEMP,
        UPLUS,
        UMINUS,
        LNOT,
        BNOT,
        CAST,
        DREF,
        ADDR,
        SIZEOF,
        ALIGNOF,
        REMAINDER,
        ADD,
        SUB,
        GT,
        LT,
        GE,
        LE,
        NE,
        EQ,
        BAND,
        BXOR,
        BOR,
        LAND,
        LOR,
        TEN,
        MOVADD,
        MOVSUB,
        MOVMUL,
        MOVDIV,
        MOVREM,
        MOVSHR,
        MOVSHL,
        MOVROL,
        MOVROR,
        MOVAND,
        MOVOR,
        MOVXOR,
        COMMA,
        SEMICOLON,

        SIN,
        COS,
        TAN,
        EXP,
        LN,
        LOG2,
        SINH,
        COSH,
        TANH,
        ASIN,
        ACOS,
        ATAN,
        SEC,
        CSC,
        COT,
        SQRT,

        HEX,
        BIN,
        OCT,
        DEC,
        POLAR
    }
	/*
	1 	++ -- 	Suffix/postfix increment and decrement 	Left-to-right
	() 	Function call
	[] 	Array subscripting
	. 	Structure and union member access
	-> 	Structure and union member access through pointer
	(type){list} 	Compound literal(C99)
	2 	++ -- 	Prefix increment and decrement 	Right-to-left
	+ - 	Unary plus and minus
	! ~ 	Logical NOT and bitwise NOT
	(type) 	Type cast
	* 	Indirection (dereference)
	& 	Address-of
	sizeof 	Size-of[note 1]
	_Alignof 	Alignment requirement(C11)
	3 	* / % 	Multiplication, division, and remainder 	Left-to-right
	4 	+ - 	Addition and subtraction
	5 	<< >> 	Bitwise left shift and right shift
	6 	< <= 	For relational operators < and ≤ respectively
	> >= 	For relational operators > and ≥ respectively
	7 	== != 	For relational = and ≠ respectively
	8 	& 	Bitwise AND
	9 	^ 	Bitwise XOR (exclusive or)
	10 	| 	Bitwise OR (inclusive or)
	11 	&& 	Logical AND
	12 	|| 	Logical OR
	13[note 2] 	?: 	Ternary conditional[note 3] 	Right-to-Left
	14 	= 	Simple assignment
	+= -= 	Assignment by sum and difference
	*= /= %= 	Assignment by product, quotient, and remainder
	<<= >>= 	Assignment by bitwise left shift and right shift
	&= ^= |= 	Assignment by bitwise AND, XOR, and OR
	15 	, 	Comma 	Left-to-right
*/

}
