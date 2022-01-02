package com.kyhsgeekcode.disassembler.utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class PrototypeParser {
    Map<String, Prototype> prototypes = new HashMap<>();

    public PrototypeParser(FileReader reader) throws IOException {
        BufferedReader br = new BufferedReader(reader);
        //reads in the file and parses prototype.
        //do not support preprocessor directives.
        //read by line
        Progress progress = Progress.RETTYPE;
        String line = br.readLine();
        Prototype proto = null;
        Prototype.Parameter par = null;
        while (line != null) {
            //parse by delims
            StringTokenizer strtok = new StringTokenizer(line, "[](){} ,", true);
            while (strtok.hasMoreElements()) {
                String word = strtok.nextToken();
                if (word.matches("\\s"))
                    continue;
                switch (progress) {
                    case RETTYPE:
                        //this word is return type
                        if ("(){}[]".contains(word)) {
                            //error();
                        }
                        proto = new Prototype();
                        proto.returnType = word;
                        progress = Progress.NAME;
                        break;
                    case NAME:
                        //this word is name
                        proto.name = word;
                        progress = Progress.LPAR;
                        break;
                    case LPAR:
                        if (word.equals("(")) {
                            progress = Progress.PARTYPE;
                            //par=new Prototype.Parameter();
                        }
                        break;
                    case PARTYPE:
                        //proto.params.add(new Parameter)
                }

            }
            line = br.readLine();
        }

    }

    public String getPrototype(String funcname) {
        return "";
    }

    enum Progress {
        RETTYPE,
        NAME,
        PARTYPE,
        PARNAME,
        LPAR
    }

}

//parser theorm
// prototype => type name ( [type parname],+) ;
// type -> [a-zA-Z]
