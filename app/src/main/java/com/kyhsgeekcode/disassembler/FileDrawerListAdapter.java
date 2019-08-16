package com.kyhsgeekcode.disassembler;

import android.view.View;

import java.util.List;

import pl.openrnd.multilevellistview.ItemInfo;
import pl.openrnd.multilevellistview.MultiLevelListAdapter;

public class FileDrawerListAdapter extends MultiLevelListAdapter {
    public FileDrawerListAdapter() {
        super();
    }

    @Override
    protected boolean isExpandable(Object object) {
        return false;
    }

    @Override
    protected List<?> getSubObjects(Object object) {
        return null;
    }

    @Override
    protected View getViewForObject(Object object, View convertView, ItemInfo itemInfo) {
        return null;
    }

    @Override
    public void setDataItems(List<?> dataItems) {
        super.setDataItems(dataItems);
    }

    @Override
    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
    }
}
