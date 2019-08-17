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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import pl.openrnd.multilevellistview.ItemInfo;
import pl.openrnd.multilevellistview.MultiLevelListAdapter;

import static com.kyhsgeekcode.disassembler.FileDrawerListItem.DrawerItemType.HEAD;

public class FileDrawerListAdapter extends MultiLevelListAdapter {
    private final Context context;
    boolean mAlwaysExpandend = false;

    public FileDrawerListAdapter(Context context) {
        super();
        Log.i("TEST", "COnstructor");
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
        int initialLevel = item.level;
        int newLevel = initialLevel + 1;
        switch (item.type) {
            case HEAD: {
                switch ((int) item.tag) {
                    case MainActivity.TAG_INSTALLED:
                        final PackageManager pm = context.getPackageManager();
                        List<ApplicationInfo> ais = pm.getInstalledApplications(0);
                        ais.sort(new Comparator<ApplicationInfo>() {
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
                try {
                    ZipFile zipFile = new ZipFile(path);
                    Enumeration zipEntries = zipFile.entries();
                    while (zipEntries.hasMoreElements()) {
                        String fileName = ((ZipEntry) zipEntries.nextElement()).getName();
                        items.add(new FileDrawerListItem(new File(fileName), newLevel));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        //if expandable yes.
        //if folder show subfolders
        //if zip/apk unzip and show
        return items;
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
        Log.d("FileAdapter", "Level:" + item.level);
        viewHolder.nameView.setPaddingRelative(item.level * 30, 0, 0, 0);
        return convertView;
    }

    private Drawable getDrawableFromType(FileDrawerListItem.DrawerItemType type) {
        return context.getDrawable(iconTable.get(type));
    }

    private static final Map<FileDrawerListItem.DrawerItemType, Integer> iconTable = new HashMap<>();

    static {
        iconTable.put(FileDrawerListItem.DrawerItemType.APK, R.drawable.apk);
        iconTable.put(FileDrawerListItem.DrawerItemType.BINARY, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.DEX, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.DISASSEMBLY, R.drawable.doc);
        iconTable.put(FileDrawerListItem.DrawerItemType.FOLDER, R.drawable.ic_folder_icon);
        iconTable.put(HEAD, R.drawable.ic_folder_icon);
        iconTable.put(FileDrawerListItem.DrawerItemType.NORMAL, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE_IL, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PROJECT, R.drawable.ic_launcher);
        iconTable.put(FileDrawerListItem.DrawerItemType.ZIP, R.drawable.zip);
    }
}
