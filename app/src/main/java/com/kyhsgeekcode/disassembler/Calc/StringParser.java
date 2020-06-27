package com.kyhsgeekcode.disassembler.Calc;

import android.util.Log;

import java.util.Set;

public class StringParser {
    int i = 0;
    Set<String> str2opks = null;
    Set<Character> ch2opks = null;
    private String TAG = "Disassembler parser";
    private String source;
    private char[] chars;

    public StringParser(String s) {
        source = s;
        chars = s.toCharArray();
    }

    public Token getToken() {
        //delim: space, nl, ops,
        if (i >= chars.length)
            return null;
        try {
            while (i < chars.length && Character.isWhitespace(chars[i])) {
                i++;
                Log.v(TAG, "Skipping whsp,i=" + i);
            }
            int s = i;
            Log.v(TAG, "s=" + s);
            while (i < chars.length && (Character.isJavaIdentifierPart(chars[i]) || chars[i] == '.')) {
                i++;
                //Log.v(TAG,"JavaId"+i);
            }
            if (i != s) {
                String str = new String(chars, s, i - s);
                if (Operator.str2op.containsKey(str)) {
                    return new Operator(str);
                } else {
                    return new Token(str);
                }
            }

            //TODO: CHECK MORE CHARS
            if (str2opks == null)
                str2opks = Operator.str2op.keySet();
            for (String chs : Operator.keyList) {
                int reqlen = chs.length();
                Log.v(TAG, "chs=" + chs + reqlen);
                Log.v(TAG, "i=" + i);
                if (i + reqlen - 1 >= chars.length) {
                    Log.v(TAG, "failed len test");
                    continue;
                }
                String chks = new String(chars, i, reqlen);
                Log.v(TAG, "cks=" + chks);
                if (chs.compareTo(chks) == 0) {
                    i += reqlen;
                    return new Operator(chs);
                }
            }
            if (ch2opks == null)
                ch2opks = Operator.ch2op.keySet();

            if (i < chars.length) {
                Log.v(TAG, "ci=" + chars[i]);
                for (Character c : ch2opks) {
                    Log.v(TAG, "c=" + c.charValue());
                    if (c.charValue() == chars[i])
                        return new Operator(chars[i++]);
                }
            }
			/*if(i<chars.length&&"+-/\"\'&():;!?~|×÷^={}[]".indexOf(chars[i])>=0){
				Log.v(TAG,"op"+chars[i]);
				return new Operator(chars[i++]);
			}*/
            //while(i<chars.length&&chars[i]=='*')
            //	i++;
            i++;
            return new Token("Invalid token");// Operator(chars,s,i-s);
        } catch (ArrayIndexOutOfBoundsException e) {
            Log.d(TAG, "", e);
        }
        return null;
    }
}
