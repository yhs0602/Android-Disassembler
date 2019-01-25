package com.kyhsgeekcode.disassembler.Calc;

public class Token
{
	public Token(char[] src, int start, int n)
	{
		String s=new String(src,start,n);
		if(Character.isDigit(src[start]))
		{
			data=new Data(Double.parseDouble(s));
		} else {
			//Var or functions
			name=s;
			data= new Data(0);
		}
		//TODO
		type=Type.OPERAND;
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
	Data data;
	public Data getValue()
	{
		return data;
	}
	public Token(Data data)
	{
		this.data=data;
	}
	@Override
	public String toString()
	{
		return "name="+name+",type="+type+",data="+data;
	}
	
}
