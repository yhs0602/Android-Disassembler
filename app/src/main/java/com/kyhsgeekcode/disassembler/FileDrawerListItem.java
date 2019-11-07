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

import at.pollaknet.api.facile.FacileReflector;
import at.pollaknet.api.facile.code.ExceptionClause;
import at.pollaknet.api.facile.code.MethodBody;
import at.pollaknet.api.facile.code.instruction.CilInstruction;
import at.pollaknet.api.facile.renderer.ILAsmRenderer;
import at.pollaknet.api.facile.symtab.symbols.Method;
import at.pollaknet.api.facile.symtab.symbols.TypeRef;

public class FileDrawerListItem {
    private static final String TAG = "FileItem";
    String caption;
    Object tag;         //number or path or object
    Drawable drawable;
    int level;
    boolean isInZip = false;

    public String CreateDataToPath(File root) {
        if ((tag instanceof Object[]) && (((Object[]) tag).length > 1) && (((Object[]) tag)[0] instanceof FacileReflector) && (((Object[]) tag)[1] instanceof Method)) {
            Method method = (Method) ((Object[]) tag)[1];
            FacileReflector reflector = (FacileReflector) ((Object[]) tag)[0];
            MethodBody mb = method.getMethodBody();
            //mb.toString();
            File outDir = new File(root, "temp-cil/");
            outDir.mkdirs();
            File outFile = new File(outDir, method.getName().replaceAll("[^a-zA-Z0-9._]+", "_") + ".il");
            try {
                FileWriter fr = new FileWriter(outFile);
                StringBuffer buffer = new StringBuffer(256);
                buffer.append("Method Body:");
                buffer.append(String.format("\n\t Flags: 0x%04x", mb.getFlags()));
                buffer.append("\tHeaderSize: ");
                buffer.append(mb.getHeaderSize());
                buffer.append(" bytes");
                buffer.append("\n\tCodeSize: ");
                buffer.append(mb.getCodeSize());
                buffer.append(" bytes");
                buffer.append("\tMaxStack: ");
                buffer.append(mb.getMaxStack());
                buffer.append(String.format("\tToken: 0x%08x", mb.getLocalVarSignatureToken()));
                int index = 0;
                int var5;
                if (mb.getLocalVars() != null) {
                    buffer.append("\n\n\t Locals:");
                    TypeRef[] var6;
                    var5 = (var6 = mb.getLocalVars()).length;

                    for (int var4 = 0; var4 < var5; ++var4) {
                        TypeRef typeRef = var6[var4];
                        buffer.append("\n\t\t");
                        buffer.append(typeRef.getFullQualifiedName());
                        buffer.append(" $");
                        buffer.append(index);
                        buffer.append(";");
                        ++index;
                    }
                }

                buffer.append("\n\n\tCIL: ");
                int programCounter = 0;
                CilInstruction[] var7;
                int var11 = (var7 = mb.getCilInstructions()).length;

                for (var5 = 0; var5 < var11; ++var5) {
                    CilInstruction i = var7[var5];
                    buffer.append(String.format("\nIL_%04x: %s", programCounter, i.render(new ILAsmRenderer(reflector))));
                    programCounter += i.getByteSize();
                }

                if (mb.getExceptionClauses() != null) {
                    buffer.append("\n\n\tExceptions: ");
                    ExceptionClause[] var12;
                    var11 = (var12 = mb.getExceptionClauses()).length;

                    for (var5 = 0; var5 < var11; ++var5) {
                        ExceptionClause ex = var12[var5];
                        buffer.append("\n\t\t");
                        buffer.append(ex.toString());
                    }
                }
                fr.write(buffer.toString());
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
            } else if (lower.endsWith(".so") || lower.endsWith(".elf") || lower.endsWith(".o") || lower.endsWith(".bin")
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
