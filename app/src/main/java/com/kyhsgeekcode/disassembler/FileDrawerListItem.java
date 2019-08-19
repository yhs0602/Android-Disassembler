package com.kyhsgeekcode.disassembler;

import android.graphics.drawable.Drawable;
import android.util.Log;

import org.boris.pecoff4j.ImageDataDirectory;
import org.boris.pecoff4j.PE;
import org.boris.pecoff4j.io.PEParser;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import at.pollaknet.api.facile.code.MethodBody;
import at.pollaknet.api.facile.symtab.symbols.Method;

public class FileDrawerListItem {
    private static final String TAG = "FileItem";
    String caption;
    Object tag;         //number or path
    Drawable drawable;
    int level;
    boolean isInZip = false;

    public String CreateDataToPath(File root) {
        if (tag instanceof Method) {
            Method method = (Method) tag;
            MethodBody mb = method.getMethodBody();
            mb.toString();
            File outDir = new File(root, "temp-cil/");
            outDir.mkdirs();
            File outFile = new File(outDir, ((Method) tag).getName().replaceAll("[^a-zA-Z0-9\\._]+", "_") + ".il");
            try {
                FileWriter fr = new FileWriter(outFile);
                fr.write(mb.toString());
                fr.close();
            } catch (IOException e) {
                Log.e(TAG, "", e);
            }
            return outFile.getAbsolutePath();
        }
        return null;
    }

    public enum DrawerItemType {
        FOLDER,
        ZIP,
        APK,
        NORMAL,
        BINARY,
        PE,
        PE_IL,
        PE_IL_TYPE,
        FIELD,
        METHOD,
        DEX,
        PROJECT,
        DISASSEMBLY,
        HEAD,
        NONE
    }


    DrawerItemType type;

    public FileDrawerListItem(String caption, DrawerItemType type, int tag, int level) {
        this.caption = caption;
        this.type = type;
        this.tag = tag;
        this.level = level;
    }

    public FileDrawerListItem(String caption, Drawable drawable, int level) {
        this.caption = caption;
        this.drawable = drawable;
        this.type = DrawerItemType.NONE;
        this.level = level;
    }

    public FileDrawerListItem(String caption, DrawerItemType type, Object tag, int level) {
        this.caption = caption;
        this.type = type;
        this.tag = tag;
        this.level = level;
    }

    public FileDrawerListItem(File file, int level) {
        Log.d(TAG, "drawerlistitem" + file.getPath());
        caption = file.getName();
        if (file.isDirectory() && !caption.endsWith("/"))
            caption += "/";
        tag = file.getPath();
        if (file.isDirectory()) {
            type = DrawerItemType.FOLDER;
        } else {
            String lower = caption.toLowerCase();
            if (lower.endsWith(".zip"))
                type = DrawerItemType.ZIP;
            else if (lower.endsWith(".apk"))
                type = DrawerItemType.APK;
            else if (lower.endsWith("assembly-csharp.dll"))
                type = DrawerItemType.PE_IL;
            else if (lower.endsWith(".exe") || lower.endsWith(".sys") || lower.endsWith(".dll")) {
                type = DrawerItemType.PE;
                try {
                    PE pe = PEParser.parse(file.getPath());
                    //https://web.archive.org/web/20110930194955/http://www.grimes.demon.co.uk/dotnet/vistaAndDotnet.htm
                    //Not fourteenth, but 15th
                    //for(int i=0;i<20;i++) {
                    ImageDataDirectory idd = pe.getOptionalHeader().getDataDirectory(14);
                    //    Log.d(TAG, "i:"+i+", size:" + idd.getSize() + ", address:" + idd.getVirtualAddress());
                    if (idd.getSize() != 0 && idd.getVirtualAddress() != 0)
                        type = DrawerItemType.PE_IL;
                    //}
                } catch (IOException | ArrayIndexOutOfBoundsException | NullPointerException e) {
                    Log.e(TAG, "", e);
                    //e.printStackTrace();
                }
            }
            else if (lower.endsWith(".so") || lower.endsWith(".elf") || lower.endsWith(".o") || lower.endsWith(".bin")
                    || lower.endsWith(".axf") || lower.endsWith(".prx") || lower.endsWith(".puff") || lower.endsWith(".ko") || lower.endsWith(".mod"))
                type = DrawerItemType.BINARY;
            else if (lower.endsWith(".dex"))
                type = DrawerItemType.DEX;
            else if (lower.endsWith(".asm"))
                type = DrawerItemType.DISASSEMBLY;
            else if (lower.endsWith(".adp"))
                type = DrawerItemType.PROJECT;
            else
                type = DrawerItemType.NORMAL;
        }
        this.level = level;
    }

    public boolean IsExpandable() {
        return expandables.contains(type);
    }

    public boolean isOpenable() {
        return !inopenables.contains(type);
    }

    private static final Set<DrawerItemType> expandables = new HashSet<>();
    private static final Set<DrawerItemType> inopenables = new HashSet<>();

    static {
        expandables.add(DrawerItemType.APK);
        expandables.add(DrawerItemType.ZIP);
        expandables.add(DrawerItemType.FOLDER);
        expandables.add(DrawerItemType.HEAD);
        expandables.add(DrawerItemType.DEX);
        expandables.add(DrawerItemType.PE_IL);
        expandables.add(DrawerItemType.PE_IL_TYPE);
    }

    static {
        inopenables.add(DrawerItemType.FIELD);

    }
}
