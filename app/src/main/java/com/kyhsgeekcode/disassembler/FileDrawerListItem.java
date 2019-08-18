package com.kyhsgeekcode.disassembler;

import android.graphics.drawable.Drawable;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class FileDrawerListItem {
    String caption;
    Object tag;         //number or path
    Drawable drawable;
    int level;
    boolean isInZip = false;
    public enum DrawerItemType {
        FOLDER,
        ZIP,
        APK,
        NORMAL,
        BINARY,
        PE,
        PE_IL,
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

    public FileDrawerListItem(File file, int level) {
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
            else if (lower.endsWith("Assembly-CSharp.dll"))
                type = DrawerItemType.PE_IL;
            else if (lower.endsWith(".exe") || lower.endsWith(".sys") || lower.endsWith(".dll"))
                type = DrawerItemType.PE;
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

    private static final Set<DrawerItemType> expandables = new HashSet<>();

    static {
        expandables.add(DrawerItemType.APK);
        expandables.add(DrawerItemType.ZIP);
        expandables.add(DrawerItemType.FOLDER);
        expandables.add(DrawerItemType.HEAD);
        expandables.add(DrawerItemType.DEX);
        expandables.add(DrawerItemType.PE_IL);
    }
}
