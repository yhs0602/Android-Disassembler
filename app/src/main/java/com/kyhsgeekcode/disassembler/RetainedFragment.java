package com.kyhsgeekcode.disassembler;


import android.os.Bundle;

import androidx.fragment.app.Fragment;

public class RetainedFragment extends Fragment {

    // data object we want to retain
    private DisassemblyManager data;
    private byte[] filecontent;
    private AbstractFile parsedFile;
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public AbstractFile getParsedFile() {
        return parsedFile;
    }

    public void setParsedFile(AbstractFile elfUtil) {
        this.parsedFile = elfUtil;
    }

    public byte[] getFilecontent() {
        return filecontent;
    }

    public void setFilecontent(byte[] filecontent) {
        this.filecontent = filecontent;
    }

    // this method is only called once for this fragment
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // retain this fragment
        setRetainInstance(true);
    }

    public DisassemblyManager getDisasmManager() {
        return data;
    }

    public void setDisasmManager(DisassemblyManager data) {
        this.data = data;
    }
}
