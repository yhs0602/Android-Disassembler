package com.kyhsgeekcode.disassembler;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Queue;

public class LogAdapter extends BaseAdapter {
    private static String TAG = "LogAdapter";
    private ArrayList<LogData> listViewItemList = new ArrayList<>();

    public LogAdapter() {

    }

    public void Refresh() {
        Queue<LogData> data = Logger.getLogData();
        listViewItemList = new ArrayList<>(data);
        notifyDataSetChanged();
    }

    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
    @Override
    public int getCount() {
        return listViewItemList.size();
    }

    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        final int pos = position;
        final Context context = parent.getContext();

        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.logview_item, parent, false);
        }

        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
        TextView levelTextView = (TextView) convertView.findViewById(R.id.textViewLogLevel);
        TextView timeTextView = (TextView) convertView.findViewById(R.id.textViewLogTime);
        TextView descTextView = (TextView) convertView.findViewById(R.id.textViewLogDesc);
        TextView tagTextView = convertView.findViewById(R.id.textViewLogTag);
        {
            // Data Set(listViewItemList)에서 position에 위치한 데이터 참조 획득
            LogData listViewItem = listViewItemList.get(position);
            tagTextView.setText(listViewItem.TAG);
            levelTextView.setText("" + listViewItem.level.charAt(0));
            timeTextView.setText(listViewItem.time);
            descTextView.setText(listViewItem.description);
        }
        return convertView;
    }

    // 지정한 위치(position)에 있는 데이터와 관계된 아이템(row)의 ID를 리턴. : 필수 구현
    @Override
    public long getItemId(int position) {
        return position;
    }

    // 지정한 위치(position)에 있는 데이터 리턴 : 필수 구현
    @Override
    public Object getItem(int position) {
        return listViewItemList.get(position);
    }
}
