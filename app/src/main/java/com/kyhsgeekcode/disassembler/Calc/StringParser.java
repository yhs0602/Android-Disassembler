package com.kyhsgeekcode.disassembler.Calc;


public class StringParser
{
	public StringParser(String s)
	{
		source=s;
		chars=s.toCharArray();
	}
	public Token getToken(){
		//delim: space, nl, ops,
		try{
			while(Character.isWhitespace(chars[i]))
				i++;
			int s=i;
			while(Character.isJavaIdentifierPart(chars[i]))
				i++;
			if(i!=s)
				return new Token(chars,s,i-s);
			if("+-/\"\'&():;!?~|×÷^={}[]".indexOf(chars[i])>=0)
				return new Operator(chars[i]);
			while(chars[i]=='*')
				i++;
			return new Operator(chars,s,i);
		}catch(ArrayIndexOutOfBoundsException e){}
		return null;
	}
	private String source;
	private char[] chars;
	int i;
}
