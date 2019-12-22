package com.kyhsgeekcode.disassembler;

import android.app.Activity;
import android.content.Context;

import com.kyhsgeekcode.disassembler.FileTabFactory.FileTabContentFactory;
import com.kyhsgeekcode.disassembler.FileTabFactory.ImageFileTabFactory;
import com.kyhsgeekcode.disassembler.FileTabFactory.NativeDisassemblyFactory;
import com.kyhsgeekcode.disassembler.FileTabFactory.StringFoundFactory;
import com.kyhsgeekcode.disassembler.FileTabFactory.TextFileTabFactory;

import java.util.ArrayList;
import java.util.List;

public class FileContext {
    private final Context context;
    private final Analyzer analyzer;
    AbstractFile file;

    private FileTabContentFactory textFactory;
    private FileTabContentFactory imageFactory;
    private FileTabContentFactory nativeDisasmFactory;
    private FileTabContentFactory stringFoundFactory;
    final List<FileTabContentFactory> factoryList = new ArrayList<>();

    public FileContext(Activity context, AbstractFile file) {
        this.file = file;
        this.context = context;
        analyzer = new Analyzer(file.fileContents);
        textFactory = new TextFileTabFactory(context);
        imageFactory = new ImageFileTabFactory(context);
        nativeDisasmFactory = new NativeDisassemblyFactory(context);
        stringFoundFactory = new StringFoundFactory(context, analyzer);
        factoryList.add(textFactory);
        factoryList.add(imageFactory);
        factoryList.add(nativeDisasmFactory);
        factoryList.add(stringFoundFactory);
    }

    public AbstractFile getFile() {
        return file;
    }

    public FileTabContentFactory OpenNewTab(TabType type) {
        FileTabContentFactory factory = factoryList.get(type.ordinal());
        factory.setType(file.getPath(), type);
        return factory;
    }
}
