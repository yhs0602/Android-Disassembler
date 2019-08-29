package com.kyhsgeekcode.disassembler;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Environment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import org.jf.baksmali.Main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import at.pollaknet.api.facile.Facile;
import at.pollaknet.api.facile.FacileReflector;
import at.pollaknet.api.facile.symtab.TypeKind;
import at.pollaknet.api.facile.symtab.symbols.Constant;
import at.pollaknet.api.facile.symtab.symbols.Field;
import at.pollaknet.api.facile.symtab.symbols.Method;
import at.pollaknet.api.facile.symtab.symbols.Type;
import at.pollaknet.api.facile.symtab.symbols.scopes.Assembly;
import pl.openrnd.multilevellistview.ItemInfo;
import pl.openrnd.multilevellistview.MultiLevelListAdapter;

import static com.kyhsgeekcode.disassembler.FileDrawerListItem.DrawerItemType.HEAD;

public class FileDrawerListAdapter extends MultiLevelListAdapter {
    private static final String TAG = "FileAdapter";
    private final Context context;
    boolean mAlwaysExpandend = false;

    public FileDrawerListAdapter(Context context) {
        super();
        this.context = context;
    }

    @Override
    protected boolean isExpandable(Object object) {
        FileDrawerListItem item = (FileDrawerListItem) object;
        return item.IsExpandable();
    }

    @Override
    protected List<?> getSubObjects(Object object) {
        List<FileDrawerListItem> items = new ArrayList<>();
        FileDrawerListItem item = (FileDrawerListItem) object;

        //Moved From MainActivity.java
        Toast.makeText(context, item.caption, Toast.LENGTH_SHORT).show();
        //

        int initialLevel = item.level;
        int newLevel = initialLevel + 1;
        switch (item.type) {
            case HEAD: {
                switch ((int) item.tag) {
                    case MainActivity.TAG_INSTALLED:
                        final PackageManager pm = context.getPackageManager();
                        List<ApplicationInfo> ais = pm.getInstalledApplications(0);
                        Collections.sort(ais, new Comparator<ApplicationInfo>() {
                            @Override
                            public int compare(ApplicationInfo o1, ApplicationInfo o2) {
                                String applabel1 = (String) pm.getApplicationLabel(o1);
                                String applabel2 = (String) pm.getApplicationLabel(o2);
                                return applabel1.compareTo(applabel2);
                            }
                        });
                        for (ApplicationInfo ai : ais) {
                            String applabel = (String) pm.getApplicationLabel(ai);
                            String caption = applabel + "(" + ai.packageName + ")";
                            Drawable drawable;
                            try {
                                drawable = pm.getApplicationIcon(ai.packageName);
                            } catch (PackageManager.NameNotFoundException e) {
                                Log.e("FileAdapter", "Fail icon", e);
                                drawable = context.getDrawable(android.R.drawable.sym_def_app_icon);
                            }

                            FileDrawerListItem newitem = new FileDrawerListItem(caption, drawable, newLevel);
                            newitem.tag = ai.sourceDir;
                            newitem.type = FileDrawerListItem.DrawerItemType.APK;
                            items.add(newitem);
                        }
                        break;
                    case MainActivity.TAG_STORAGE:
                        items.add(new FileDrawerListItem(new File("/"), newLevel));
                        items.add(new FileDrawerListItem(Environment.getExternalStorageDirectory(), newLevel));
                        break;
                    case MainActivity.TAG_PROJECTS:
                        items.add(new FileDrawerListItem("Not implemented :O", context.getDrawable(android.R.drawable.ic_secure), newLevel));
                        break;
                    case MainActivity.TAG_PROCESSES:
                        items.add(new FileDrawerListItem("Not implemented :0", context.getDrawable(android.R.drawable.ic_secure), newLevel));
                        break;
                    case MainActivity.TAG_RUNNING_APPS:
                        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                        List<ActivityManager.RunningAppProcessInfo> runnings = am.getRunningAppProcesses();
                        for (ActivityManager.RunningAppProcessInfo info : runnings) {
                            String caption = info.processName + " (pid " + info.pid + ", uid " + info.uid + ")";
                            //info.pkgList
                            items.add(new FileDrawerListItem(caption, context.getDrawable(android.R.drawable.ic_secure), newLevel));
                        }
                        break;

                }
            }
            break;
            case FOLDER: {
                String path = (String) item.tag;
                File thisFolder = new File(path);
                if (thisFolder.isDirectory()) {
                    if (thisFolder.canRead()) {
                        File[] files = thisFolder.listFiles();
                        if (files.length > 0) {
                            for (File file : files) {
                                items.add(new FileDrawerListItem(file, newLevel));
                            }
                            Collections.sort(items, new Comparator<FileDrawerListItem>() {
                                @Override
                                public int compare(FileDrawerListItem p1, FileDrawerListItem p2) {
                                    int cdir = compareDir(p1, p2);
                                    if (cdir == 0) {
                                        if (p1.caption.endsWith("/")) {
                                            if (p1.caption.equals("/")) {
                                                return -1;
                                            }
                                            if (p2.caption.equals("/")) {
                                                return 1;
                                            }
                                            if (p1.caption.equals("../")) {
                                                return -1;
                                            }
                                            if (p2.caption.equals("../")) {
                                                return 1;
                                            }
                                            return p1.caption.compareTo(p2.caption);
                                        } else {
                                            return p1.caption.compareTo(p2.caption);
                                        }
                                    } else {
                                        return cdir;
                                    }
                                }

                                int compareDir(FileDrawerListItem p1, FileDrawerListItem p2) {
                                    if (p1.caption.endsWith("/")) {
                                        if (p2.caption.endsWith("/")) {
                                            return 0;
                                        } else {
                                            return -1;
                                        }
                                    } else if (p2.caption.endsWith("/")) {
                                        return 1;
                                    }
                                    return p1.caption.compareTo(p2.caption);
                                }
                            });
                        } else {
                            items.add(new FileDrawerListItem("The folder is empty", context.getDrawable(android.R.drawable.ic_secure), newLevel));
                        }
                    } else {
                        items.add(new FileDrawerListItem("Could not be read!", context.getDrawable(android.R.drawable.ic_secure), newLevel));
                    }
                }
            }
            break;
            case ZIP:
            case APK: {
                String path = (String) item.tag;
                File targetDirectory = new File(new File(context.getFilesDir(), "/extracted/"), new File(path).getName() + "/");
                targetDirectory.mkdirs();
                try {
                    ZipInputStream zi = new ZipInputStream(new FileInputStream(path));
                    ZipEntry entry;
                    byte[] buffer = new byte[2048];
                    while ((entry = zi.getNextEntry()) != null) {
                        File outfile = new File(targetDirectory, entry.getName());
                        String canonicalPath = outfile.getCanonicalPath();
                        if (!canonicalPath.startsWith(targetDirectory.getCanonicalPath())) {
                            throw new SecurityException("The file may have a Zip Path Traversal Vulnerability." +
                                    "Is the file trusted?");
                        }
                        outfile.getParentFile().mkdirs();
                        FileOutputStream output = null;
                        try {
                            output = new FileOutputStream(outfile);
                            int len = 0;
                            while ((len = zi.read(buffer)) > 0) {
                                output.write(buffer, 0, len);
                            }
                        } finally {
                            // we must always close the output file
                            if (output != null) output.close();
                        }
                    }
                    return getSubObjects(new FileDrawerListItem(targetDirectory, initialLevel));
                } catch (IOException e) {
                    Log.e("FileAdapter", "", e);
                    items.add(new FileDrawerListItem("NO", context.getDrawable(android.R.drawable.ic_secure), newLevel));
                }
            }
            break;
            case DEX:
                String filename = (String) item.tag;
                File targetDirectory = new File(new File(context.getFilesDir(), "/dex-decompiled/"), new File(filename).getName() + "/");
                targetDirectory.mkdirs();
                Main.main(new String[]{"d", "-o", targetDirectory.getAbsolutePath(), filename});
                return getSubObjects(new FileDrawerListItem(targetDirectory, initialLevel));
            case PE_IL:
                try {
                    FacileReflector facileReflector = Facile.load((String) item.tag);
                    //load the assembly
                    Assembly assembly = facileReflector.loadAssembly();
                    Type[] types = assembly.getAllTypes();
                    for (Type type : types) {
                        items.add(new FileDrawerListItem(type.getNamespace() + "." + type.getName(), FileDrawerListItem.DrawerItemType.PE_IL_TYPE, new Object[]{facileReflector, type}, newLevel));
                    }
                } catch (Exception e) {
                    Logger.e("FileAdapter", "", e);
                }
                break;
            case PE_IL_TYPE:
                Object[] cont = (Object[]) item.tag;
                FacileReflector fr = (FacileReflector) cont[0];
                Type type = (Type) cont[1];
                Field[] fields = type.getFields();
                Method[] methods = type.getMethods();
                for (Field field : fields) {
                    Constant c = field.getConstant();
                    String fieldDesc = field.getName() + ":" + field.getTypeRef().getName();
                    if (c != null) {
                        int kind = c.getElementTypeKind();
                        byte[] bytes = c.getValue();
                        Object value = getValueFromTypeKindAndBytes(bytes, kind);
                        fieldDesc += "(=";
                        fieldDesc += value;
                        fieldDesc += ")";
                    }
                    items.add(new FileDrawerListItem(fieldDesc, FileDrawerListItem.DrawerItemType.FIELD, null, newLevel));
                }
                for (Method method : methods) {
                    items.add(new FileDrawerListItem(method.getName() + method.getMethodSignature(), FileDrawerListItem.DrawerItemType.METHOD, new Object[]{fr, method}, newLevel));
                }
                break;
        }

        //if expandable yes.
        //if folder show subfolders
        //if zip/apk unzip and show
        return items;
    }

    private Object getValueFromTypeKindAndBytes(byte[] bytes, int kind) {
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        switch (kind) {
            case TypeKind
                    .ELEMENT_TYPE_BOOLEAN:
                return (bytes[0] != 0);
            case TypeKind.ELEMENT_TYPE_CHAR:
                return (char) bytes[0];
            case TypeKind.ELEMENT_TYPE_I:
                return bb.getInt();
            case TypeKind.ELEMENT_TYPE_I1:
                return bb.get();
            case TypeKind.ELEMENT_TYPE_I2:
                return bb.getShort();
            case TypeKind.ELEMENT_TYPE_I4:
                return bb.getInt();
            case TypeKind.ELEMENT_TYPE_I8:
                return bb.getLong();
            case TypeKind.ELEMENT_TYPE_U:
                return bb.getLong();
            case TypeKind.ELEMENT_TYPE_U1:
                return bb.get() & 0xFF;
            case TypeKind.ELEMENT_TYPE_U2:
                return bb.getShort() & 0xFFFF;
            case TypeKind.ELEMENT_TYPE_U4:
                return bb.getInt();
            case TypeKind.ELEMENT_TYPE_U8:
                return bb.getLong();
            case TypeKind.ELEMENT_TYPE_R4:
                return bb.getFloat();
            case TypeKind.ELEMENT_TYPE_R8:
                return bb.getDouble();
            case TypeKind.ELEMENT_TYPE_STRING:
                return new String(bytes);
            default:
                return "Unknown!!!!";
        }
    }

    private class ViewHolder {
        TextView nameView;
        //ImageView arrowView;
    }

    @Override
    protected View getViewForObject(Object object, View convertView, ItemInfo itemInfo) {
        ViewHolder viewHolder;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = LayoutInflater.from(context).inflate(R.layout.filedraweritem, null);
            viewHolder.nameView = (TextView) convertView.findViewById(R.id.fileDrawerTextView);
            //viewHolder.levelBeamView = (LevelBeamView) convertView.findViewById(R.id.dataItemLevelBeam);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }

        FileDrawerListItem item = (FileDrawerListItem) object;
        viewHolder.nameView.setText(item.caption);
        Drawable[] compounds = new Drawable[4];
        if (itemInfo.isExpandable() && !mAlwaysExpandend) {
            compounds[0] = context.getDrawable(itemInfo.isExpanded() ?
                    android.R.drawable.arrow_up_float : android.R.drawable.arrow_down_float);
        } else {
            compounds[0] = null;
        }

        compounds[3] = item.drawable == null ? getDrawableFromType(item.type) : item.drawable;
        for (Drawable drawable : compounds) {
            if (drawable != null) {
                drawable.setBounds(0, 0, 40, 40);
            }
        }
        viewHolder.nameView.setCompoundDrawablesRelative(compounds[0], compounds[1], compounds[2], compounds[3]);
        //viewHolder.levelBeamView.setLevel(itemInfo.getLevel());
        //Log.d("FileAdapter", "Level:" + item.level);
        viewHolder.nameView.setPaddingRelative(item.level * 30, 0, 0, 0);
        return convertView;
    }

    private Drawable getDrawableFromType(FileDrawerListItem.DrawerItemType type) {
        Log.d(TAG, "type=" + type.name());
        Integer i = iconTable.get(type);
        if (i == null)
            i = android.R.drawable.ic_delete;
        return context.getDrawable(i);
    }

    private static final Map<FileDrawerListItem.DrawerItemType, Integer> iconTable = new HashMap<>();

    static {
        iconTable.put(FileDrawerListItem.DrawerItemType.APK, R.drawable.apk);
        iconTable.put(FileDrawerListItem.DrawerItemType.BINARY, R.drawable.ic_bin);
        iconTable.put(FileDrawerListItem.DrawerItemType.DEX, R.drawable.ic_dex);
        iconTable.put(FileDrawerListItem.DrawerItemType.DISASSEMBLY, R.drawable.doc);
        iconTable.put(FileDrawerListItem.DrawerItemType.FOLDER, R.drawable.ic_folder_icon);
        iconTable.put(HEAD, R.drawable.ic_folder_icon);
        iconTable.put(FileDrawerListItem.DrawerItemType.NORMAL, R.drawable.ic_file);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE, R.drawable.ic_executable);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE_IL, R.drawable.ic_dotnet);
        iconTable.put(FileDrawerListItem.DrawerItemType.PROJECT, R.drawable.ic_launcher);
        iconTable.put(FileDrawerListItem.DrawerItemType.ZIP, R.drawable.zip);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE_IL_TYPE, R.drawable.ic_type);
        iconTable.put(FileDrawerListItem.DrawerItemType.FIELD, R.drawable.ic_field);
        iconTable.put(FileDrawerListItem.DrawerItemType.METHOD, R.drawable.ic_method);
    }
}
