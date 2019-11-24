package com.kyhsgeekcode.disassembler;

import android.app.Activity;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

//ProjectNew instance is created when the user starts opening a zip or a apk or folder(?), or creates a project manually.
public class ProjectNew {
    private final Activity activity;
    Map<String, FileContext> files = new HashMap<>();
    String name;
    String path;

    public ProjectNew(Activity activity) {
        this.activity = activity;
    }

    public void OpenFile(String filePath) throws IOException {
        AbstractFile file = AbstractFile.createInstance(filePath);
        FileContext fc = new FileContext(activity, file);
        files.put(filePath, fc);
    }

    //Called when no tab involving the file is open.
    public void CloseFile(String filePath) {
        files.remove(filePath);
    }

    public void OpenFile(File file) throws IOException {
        OpenFile(file.getAbsolutePath());
    }
}
