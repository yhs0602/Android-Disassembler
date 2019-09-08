package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ListView;

import com.kyhsgeekcode.disassembler.R;
import com.kyhsgeekcode.disassembler.TabType;

public class NativeDisassemblyFactory extends FileTabContentFactory {
    public NativeDisassemblyFactory(Context context) {
        super(context);
    }

    @Override
    public View createTabContent(String tag) {
        LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View root = inflater.inflate(R.layout.disasmtab, null);
        ListView listview = root.findViewById(R.id.disasmTabListview);
        //ListViewAdapter adapter = new ListViewAdapter(null, colorHelper, MainActivity.this);
        //listview.setAdapter(adapter);
        return root;
    }

    @Override
    public void setType(String absolutePath, TabType type) {
        super.setType(absolutePath, type);
    }
}
