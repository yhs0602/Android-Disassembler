package com.kyhsgeekcode.disassembler;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;

public class FileContext {
    private final Context context;
    private final Analyzer analyzer;
    AbstractFile file;
    View stringView;
    View disasmView;
    View textView;
    View importSymView;
    View exportSymView;
    View statisticView;
    View hexView;
    FoundStringAdapter strAdapter = new FoundStringAdapter();

    public FileContext(Activity context, AbstractFile file) {
        this.file = file;
        this.context = context;
        analyzer = new Analyzer(file.fileContents);

    }

    public AbstractFile getFile() {
        return file;
    }

    public View getStringView() {
        //문제는 인자가 필요하다는 것이다.
        if (stringView == null) {
            LayoutInflater li = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            stringView = li.inflate(R.layout.before_data, null);
            ListView lvStrings = new ListView(context);
            strAdapter.Reset();
            lvStrings.setAdapter(strAdapter);
            ((ViewGroup) stringView).addView(lvStrings, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
            final ProgressBar pb = stringView.findViewById(R.id.progressBarGeneratingData);
            stringView.findViewById(R.id.buttonGenerateData).setOnClickListener((view) -> {
                view.setVisibility(GONE);
                pb.setVisibility(VISIBLE);
                //Ask it
                EditText et = new EditText(context);
                MainActivity.ShowEditDialog((Activity) context, "Search String", "Set minimum and maximum length of result (min-max)", et, "OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String s = et.getText().toString();
                        String[] splitt = s.split("-");
                        int min = Integer.parseInt(splitt[0]);
                        int max = Integer.parseInt(splitt[1]);
                        if (min < 1)
                            min = 1;
                        if (max < min)
                            max = min;
                        int finalMin = min;
                        int finalMax = max;
                        new Thread(() -> {
                            analyzer.searchStrings(strAdapter, pb, finalMin, finalMax);
                        }).start();
                    }
                }, "Cancel", null);
            });
        }
        return stringView;
    }

    public View getDisasmView() {
        return disasmView;
    }

    public View getTextView() {
        return textView;
    }

    public View getImportSymView() {
        return importSymView;
    }

    public View getExportSymView() {
        return exportSymView;
    }

    public View getStatisticView() {
        return statisticView;
    }

    public View getHexView() {
        return hexView;
    }

}
