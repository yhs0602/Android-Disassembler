package com.kyhsgeekcode.disassembler.Calc;

//unary operator:??
import java.util.*;

public class Operator extends Token implements Comparable<Operator>
{
	@Override
	public int compareTo(Operator p1)
	{
		
		return 0;
	}
	
	//public double 
	public Operator(String s){
		super(s,Type.OPERATOR);
	}
	public Operator(char c)
	{
		this(""+c);
	}
	public Operator(char [] src, int start, int n)
	{
		super(src,start,n);
	}
	public Data calc(Stack<Token> stack)
	{
		switch(operation)
		{
			case PLUS:
				return new Data(stack.pop().getValue().getDouble()+stack.pop().getValue().getDouble());
			case MINUS:
				return new Data(-stack.pop().getValue().getDouble()+stack.pop().getValue().getDouble());
			case MOV:
			{
				Data data1=stack.pop().getValue();
				Data dataDest=stack.pop().getValue();
				return dataDest.set(data1);
			}
			//case 
		}
		return null;
	}
	Operation operation;
	enum Operation
	{
		//order by priority
		PLUS,
		MINUS,
		MULT,
		DIV,
		SHR,
		SHL,
		ROR,
		ROL,
		POWER,
		MOV
	};
}
