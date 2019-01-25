package com.kyhsgeekcode.disassembler.Calc;


import android.util.*;

public class StringParser
{

	private String TAG="Disassembler parser";
	public StringParser(String s)
	{
		source=s;
		chars=s.toCharArray();
	}
	public Token getToken(){
		//delim: space, nl, ops,
		if(i>=chars.length)
			return null;
		try{
			while(i<chars.length&&Character.isWhitespace(chars[i])){
				i++;
				Log.v(TAG,"Skipping whsp,i="+i);
			}
			int s=i;
			Log.v(TAG,"s="+s);
			while(i<chars.length&&Character.isJavaIdentifierPart(chars[i])){
				i++;
				Log.v(TAG,"JavaId"+i);
			}
			if(i!=s)
				return new Token(chars,s,i-s);
			if(i<chars.length&&"+-/\"\'&():;!?~|×÷^={}[]".indexOf(chars[i])>=0){
				Log.v(TAG,"op"+chars[i]);
				return new Operator(chars[i++]);
			}
			while(i<chars.length&&chars[i]=='*')
				i++;
			return new Operator(chars,s,i-s);
		}catch(ArrayIndexOutOfBoundsException e){
			Log.d(TAG,"",e);
		}
		return null;
	}
	private String source;
	private char[] chars;
	int i=0;
}
