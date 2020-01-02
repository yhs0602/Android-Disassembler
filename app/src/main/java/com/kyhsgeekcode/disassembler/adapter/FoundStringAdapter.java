package com.kyhsgeekcode.disassembler.adapter;

import android.content.Context;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import com.kyhsgeekcode.disassembler.R;
import com.kyhsgeekcode.disassembler.analysis.FoundString;

import java.util.ArrayList;

public class FoundStringAdapter extends BaseAdapter {
    private static String TAG = "FoundStrAdapter";
    private ArrayList<FoundString> listViewItemList = new ArrayList<>();

    public FoundStringAdapter() {

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
            convertView = inflater.inflate(R.layout.strings_row, parent, false);
        }

        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
        TextView offsetTextView = convertView.findViewById(R.id.textViewStringOffset);
        TextView lengthTextView = convertView.findViewById(R.id.textViewStringLength);
        TextView strTextView = convertView.findViewById(R.id.textViewString);
        {
            // Data Set(listViewItemList)에서 position에 위치한 데이터 참조 획득
            FoundString listViewItem = listViewItemList.get(position);
            offsetTextView.setText(Long.toHexString(listViewItem.offset));
            lengthTextView.setText("" + listViewItem.length);
            String str = listViewItem.string;
            if (str.startsWith(".")) {
                //section name?
                strTextView.setTextColor(Color.WHITE);
                strTextView.setBackgroundColor(Color.BLACK);
            }
            if (str.contains("/")) {
                //path/url
                strTextView.setTextColor(Color.BLUE);
                strTextView.setBackgroundColor(Color.WHITE);
            }
            if (str.contains("\\")) {
                //path
                strTextView.setTextColor(Color.CYAN);
                strTextView.setBackgroundColor(Color.WHITE);
            }
            if (str.contains("@")) {
                strTextView.setTextColor(Color.RED);
                strTextView.setBackgroundColor(Color.WHITE);
            }
            if (str.startsWith("Java_")) {
                strTextView.setTextColor(Color.BLUE);
                strTextView.setBackgroundColor(Color.GREEN);
            }
            strTextView.setText(str);

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

    public void AddItem(FoundString str) {
        listViewItemList.add(str);
    }

    public void Reset() {
        listViewItemList.clear();
    }
}


