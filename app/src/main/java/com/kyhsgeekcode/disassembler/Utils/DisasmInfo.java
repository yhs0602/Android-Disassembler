package com.kyhsgeekcode.disassembler.Utils;

import java.util.ArrayList;

public class DisasmInfo {
    String filepath;
    long timestamp; //FILETIME
    long filesize;
    ArrayList<CommentInfo> comments = new ArrayList<>();

}
