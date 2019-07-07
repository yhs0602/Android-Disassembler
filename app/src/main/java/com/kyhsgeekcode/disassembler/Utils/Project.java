package com.kyhsgeekcode.disassembler.Utils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class Project {
    String name;
    File file;
    File uddfile; //= new File("");
    File detailFIle; //= new File("details.txt");
    Map<Long, String> comments = new HashMap<>();
    Map<String, ProjectExtra> extras = new HashMap<>();
    File parentFolder;

}
