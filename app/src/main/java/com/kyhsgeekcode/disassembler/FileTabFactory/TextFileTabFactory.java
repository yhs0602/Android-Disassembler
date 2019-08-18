package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.graphics.Color;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;

import org.apache.commons.io.FilenameUtils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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
        List<String> terms = TermList.get(FilenameUtils.getExtension(tag).toLowerCase());
        try {
            InputStreamReader isr = new InputStreamReader(new FileInputStream(tag));
            BufferedReader br = new BufferedReader(isr);
            String line = null;
            SpannableStringBuilder ssb = new SpannableStringBuilder();
            while ((line = br.readLine()) != null) {
                SpannableString ss = new SpannableString(line);
                for (String term : terms) {
                    int startIndex = line.indexOf(term);
                    if (startIndex == -1)
                        continue;
                    int stopIndex = startIndex + term.length();
                    ss.setSpan(spanBlue, startIndex, startIndex, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    Map<String, List<String>> TermList = new HashMap<>();

    {
        LoadTerms();
    }

    private void LoadTerms() {

    }
}
