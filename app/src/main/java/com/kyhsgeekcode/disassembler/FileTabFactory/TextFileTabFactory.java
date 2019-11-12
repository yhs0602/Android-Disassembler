package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.graphics.Color;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.CharacterStyle;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import org.apache.commons.io.FilenameUtils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TextFileTabFactory extends FileTabContentFactory {
    public TextFileTabFactory(Context context) {
        super(context);
    }

    public static final ForegroundColorSpan spanBlue = new ForegroundColorSpan(Color.BLUE);

    @Override
    public View createTabContent(String tag) {
        TextView tv = new TextView(context);
        SpannableStringBuilder ssb = new SpannableStringBuilder();
        List<String> terms = TermList.get(FilenameUtils.getExtension(tag).toLowerCase());
        try {
            InputStreamReader isr = new InputStreamReader(new FileInputStream(tag));
            BufferedReader br = new BufferedReader(isr);
            String line;
            while ((line = br.readLine()) != null) {
                //https://stackoverflow.com/a/46390973/8614565
                SpannableString ss = new SpannableString(line);
                if (terms != null) {
                    for (String term : terms) {
                        Log.v("TextFactory", "Checking:" + term);
                        int ofe = line.indexOf(term);
                        Log.v("TextFactory", "ofe:" + ofe);
                        for (int ofs = 0; ofs < line.length() && ofe != -1; ofs = ofe + 1) {
                            ofe = line.indexOf(term, ofs);
                            if (ofe == -1)
                                break;
                            else {
                                ss.setSpan(CharacterStyle.wrap(spanBlue), ofe, ofe + term.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                            }
                        }
                    }
                }
                ssb.append(ss);
                ssb.append(System.lineSeparator());
            }
            tv.setText(ssb, TextView.BufferType.SPANNABLE);
        } catch (IOException e) {
            e.printStackTrace();
            tv.setText("Could not read file!");
        }
        ScrollView sv = new ScrollView(context);
        //sv.setLa
        sv.addView(tv);
        return sv;
    }

    Map<String, List<String>> TermList = new HashMap<>();

    {
        LoadTerms();
    }

    private void LoadTerms() {
        List<String> smaliterms = new ArrayList<>();
        smaliterms.add(".class");
        smaliterms.add(".super");
        smaliterms.add(".source");
        smaliterms.add(".implements");
        smaliterms.add(".field");
        smaliterms.add(".method");
        TermList.put("smali", smaliterms);
        TermList.put("il", smaliterms);
    }
}
