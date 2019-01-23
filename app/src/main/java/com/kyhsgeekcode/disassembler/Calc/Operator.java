package com.kyhsgeekcode.disassembler.Calc;

//unary operator:??
import java.util.*;

public class Operator extends Token implements Comparable
{

	@Override
	public int compareTo(Object p1)
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
	public Token calc(Stack<Token> stack)
	{
		return null;
	}
}
