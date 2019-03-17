package com.kyhsgeekcode.disassembler;

import java.util.*;
import android.util.*;

public class Analyzer
{
	private byte [] bytes;

	private String TAG="Analyzer";
	//Analyzes code, strings, etc
	public Analyzer(byte [] bytes)
	{
		this.bytes=bytes;
	}
	//Search for strings
	public List<String> searchStrings()
	{
		List<String> list=new ArrayList<>();
		//char lastch=0;
		int strstart=-1;
		for(int i=0;i<bytes.length;++i)
		{
			char v=(char)(bytes[i]&0xFF);
			//Log.v(TAG,""+v);
			if(Character.isUnicodeIdentifierStart(v)||Character.isJavaLetterOrDigit(v))
			{
				if(strstart==-1)
					strstart=i;
			}
			if(v==0&&strstart!=-1)
			{
				String str=new String(bytes,strstart,i-strstart);
				strstart=-1;
				list.add(str);
				Log.i(TAG,str);
			}
		}
		return list;
	}
	//search for functions
}


