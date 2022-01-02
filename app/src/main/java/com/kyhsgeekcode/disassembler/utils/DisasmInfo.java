package com.kyhsgeekcode.disassembler.utils;

import java.util.ArrayList;

public class DisasmInfo {
    public String filepath;
    public long timestamp; //FILETIME
    public long filesize;
    public ArrayList<CommentInfo> comments = new ArrayList<>();
    public long entryPoint;
    public long codeBase;
    public long codeLimit;
    public long codeVirtualAddress;
}
