package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.view.View;
import android.widget.TabHost;

import com.kyhsgeekcode.disassembler.TabType;

import java.util.HashMap;
import java.util.Map;

public abstract class FileTabContentFactory implements TabHost.TabContentFactory {
    protected final Context context;

    public FileTabContentFactory(Context context) {
        this.context = context;
    }

    @Override
    public abstract View createTabContent(String tag);

    public void setType(String absolutePath, TabType type) {
        typeMap.put(absolutePath, type);
    }

    Map<String, TabType> typeMap = new HashMap<>();
}
