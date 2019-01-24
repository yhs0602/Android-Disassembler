package com.kyhsgeekcode.disassembler.Calc;
import java.util.*;

public class Calculator
{
	public static Data Calc(String infix)
	{
		return CalcPostfix(toPostfix(infix));
	}
	public static Data CalcPostfix(List<Token> postfix)
	{
		Stack<Token> operands=new Stack<>();
		for(Token tok:postfix)
		{
			if(tok.isOperand())
			{
				operands.push(tok);
			}else if (tok.isOperator())
			{
				Token t=new Token(((Operator)tok).calc(operands));
				if(t!=null)
					operands.push(t);
			}
		}
		return operands.pop().getValue();
	}
	public static List<Token> toPostfix(String infix)
	{
		StringParser sp=new StringParser(infix);
		Stack<Operator> operatorStack=new Stack<>();
		List<Token> postfix=new ArrayList<>();
		Token tok;
		while((tok=sp.getToken())!=null)
		{
			if(tok.isOperator())
			{
				if(operatorStack.isEmpty())
				{
					operatorStack.push((Operator)tok);
				}else{
					Operator op1=operatorStack.peek();
					int cmp=op1.compareTo((Operator)tok);
					if(cmp>0)
					{
						while(!operatorStack.isEmpty())
						{
							postfix.add(operatorStack.pop());
						}
						operatorStack.push((Operator)tok);
					} else if(cmp<=0)
					{
						operatorStack.push((Operator)tok);
					}
				}
			} else if ( tok.isOperand())
			{
				postfix.add(tok);
			}
		}
		while(!operatorStack.isEmpty())
		{
			postfix.add(operatorStack.pop());
		}
		return postfix;
	}
}

