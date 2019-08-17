package com.kyhsgeekcode.disassembler;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import pl.openrnd.multilevellistview.ItemInfo;
import pl.openrnd.multilevellistview.MultiLevelListAdapter;

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
        //if expandable yes.
        //if folder show subfolders
        //if zip/apk unzip and show
        Log.v("TEST", "" + object + "---" + object.toString());
        Logger.v("TEST", "" + object + "---" + object.toString());
        return null;
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
        compounds[3] = getDrawableFromType(item.type);
        for (Drawable drawable : compounds) {
            if (drawable != null) {
                drawable.setBounds(0, 0, 20, 20);
            }
        }
        viewHolder.nameView.setCompoundDrawablesRelative(compounds[0], compounds[1], compounds[2], compounds[3]);
        //viewHolder.levelBeamView.setLevel(itemInfo.getLevel());
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
        iconTable.put(FileDrawerListItem.DrawerItemType.HEAD, R.drawable.ic_folder_icon);
        iconTable.put(FileDrawerListItem.DrawerItemType.NORMAL, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PE_IL, R.drawable.link);
        iconTable.put(FileDrawerListItem.DrawerItemType.PROJECT, R.drawable.ic_launcher);
        iconTable.put(FileDrawerListItem.DrawerItemType.ZIP, R.drawable.zip);
    }
}
