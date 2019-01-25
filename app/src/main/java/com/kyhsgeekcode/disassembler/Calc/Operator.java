package com.kyhsgeekcode.disassembler.Calc;

//unary operator:??
import java.util.*;
import com.kyhsgeekcode.disassembler.Calc.Operator.*;

public class Operator extends Token implements Comparable<Operator>
{
	//returns positive if this is higher
	@Override
	public int compareTo(Operator p1)
	{
		Integer myp=op2priority.get(this.operation);
		Integer youp=op2priority.get(p1.operation);
		if(myp==null&&youp==null)
			return 0;
		if(myp==null)
			return -1;
		if(youp==null)
			return -1;
		
		return -myp.compareTo(youp);
	}
	
	//public double 
	private Operator(String s){
		super(s,Type.OPERATOR);
		if(operation==null)
		{
			operation=str2op.get(s);
		}
		if(operation==null)
			operation=Operation.PLUS;
	}
	public Operator(char c)
	{
		this(""+c);
		operation=ch2op.get(c);
		if(operation==null)
			operation=Operation.PLUS;	
	}
	public Operator(char [] src, int start, int n)
	{
		super(src,start,n);
	}
	public Data calc(Stack<Token> stack)
	{
		switch(operation)
		{
			case ADD:
				return new Data(stack.pop().getValue().getDouble()+stack.pop().getValue().getDouble());
			case SUB:
				return new Data(-(stack.pop().getValue().getDouble())+stack.pop().getValue().getDouble());
			case MOV:
			{
				Data data1=stack.pop().getValue();
				Data dataDest=stack.pop().getValue();
				return dataDest.set(data1);
			}
			case MULT:
			{
				return new Data(stack.pop().getValue().getDouble()*stack.pop().getValue().getDouble());
			}
			case DIV:
			{
				Data data1=stack.pop().getValue();
				Data data2=stack.pop().getValue();
				return new Data(data2.getDouble()/data1.getDouble());
			}
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
		SEMICOLON
	};
	static final Map<Character,Operation> ch2op=new HashMap<>();
	{
		ch2op.put('+',Operation.ADD);
		ch2op.put('-',Operation.SUB);
		ch2op.put('*',Operation.MULT);
		ch2op.put('×',Operation.MULT);
		ch2op.put('÷',Operation.DIV);
		ch2op.put('/',Operation.DIV);
		ch2op.put('=',Operation.MOV);
		ch2op.put('(',Operation.LPAR);
	}
	static final Map<String,Operation> str2op=new HashMap<>();
	{
		str2op.put(">>",Operation.SHR);
		str2op.put("<<",Operation.SHL);
		str2op.put(">>>",Operation.ROR);
		str2op.put("<<<",Operation.ROL);
		str2op.put("**",Operation.POWER);
		str2op.put("++",Operation.PINC);
		str2op.put("--",Operation.PDEC);
		//str2op.put('/',Operation.DIV);
		//str2op.put('=',Operation.MOV);
	}
	static final Map<Operation,Integer> op2priority=new HashMap<>();
	{
		op2priority.put(Operation.SINC,1);
		op2priority.put(Operation.SDEC,1);
		op2priority.put(Operation.LPAR,1);
		op2priority.put(Operation.RPAR,1);
		op2priority.put(Operation.MEMB,1);
		op2priority.put(Operation.MEMP,1);
		op2priority.put(Operation.LSUB,1);
		op2priority.put(Operation.RSUB,1);
		
		op2priority.put(Operation.PINC,2);
		op2priority.put(Operation.PDEC,2);
		op2priority.put(Operation.UPLUS,2);
		op2priority.put(Operation.UMINUS,2);
		op2priority.put(Operation.LNOT,2);
		op2priority.put(Operation.BNOT,2);
		op2priority.put(Operation.CAST,2);
		op2priority.put(Operation.DREF,2);
		op2priority.put(Operation.ADDR,2);
		op2priority.put(Operation.SIZEOF,2);
		op2priority.put(Operation.ALIGNOF,2);
		
		op2priority.put(Operation.MULT,3);
		op2priority.put(Operation.DIV,3);
		op2priority.put(Operation.REMAINDER,3);
		
		op2priority.put(Operation.ADD,4);
		op2priority.put(Operation.SUB,4);
		
		op2priority.put(Operation.SHR,5);
		op2priority.put(Operation.SHL,5);
		
		op2priority.put(Operation.GT,6);
		op2priority.put(Operation.LT,6);
		op2priority.put(Operation.GE,6);
		op2priority.put(Operation.LE,6);
		
		op2priority.put(Operation.NE,7);
		op2priority.put(Operation.EQ,7);
		
		op2priority.put(Operation.BAND,8);
		op2priority.put(Operation.BXOR,9);
		op2priority.put(Operation.BOR,10);
		
		op2priority.put(Operation.LAND,11);
		op2priority.put(Operation.LOR,12);
		
		op2priority.put(Operation.TEN,13);
		
		op2priority.put(Operation.MOV,14);
		op2priority.put(Operation.MOVADD,14);
		op2priority.put(Operation.MOVSUB,14);
		op2priority.put(Operation.MOVMUL,14);
		op2priority.put(Operation.MOVDIV,14);
		op2priority.put(Operation.MOVREM,14);
		op2priority.put(Operation.MOVSHR,14);
		op2priority.put(Operation.MOVSHL,14);
		op2priority.put(Operation.MOVROR,14);
		op2priority.put(Operation.MOVROL,14);
		op2priority.put(Operation.MOVAND,14);
		op2priority.put(Operation.MOVXOR,14);
		op2priority.put(Operation.MOVOR,14);
		
		op2priority.put(Operation.COMMA,15);
		op2priority.put(Operation.SEMICOLON,15);
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
