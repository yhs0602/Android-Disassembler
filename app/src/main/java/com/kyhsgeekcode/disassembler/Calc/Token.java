package com.kyhsgeekcode.disassembler.Calc;

public class Token
{
	public Token(){
		
	}
	public Token(char[] src, int start, int n)
	{
		
	}
	public Token(String s)
	{
		name=s;
		type=Type.OPERAND;
	}
	public Token(String s, Type t)
	{
		name=s;
		type=t;
	}

	public boolean isOperator()
	{	
		return type==Type.OPERATOR;
	}
	public boolean isOperand()
	{
		return type==Type.OPERAND;
	}
	enum Type
	{
		OPERATOR,
		OPERAND
	};
	Type type;
	String name;
}
