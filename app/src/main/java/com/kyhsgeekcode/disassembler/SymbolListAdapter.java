package com.kyhsgeekcode.disassembler;


import android.content.*;
import android.graphics.*;
import android.view.*;
import android.widget.*;
import java.util.*;

public class SymbolListAdapter extends BaseAdapter
{
    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
    private ArrayList<ELFUtil.Symbol> listViewItemList = new ArrayList<>() ;

    public SymbolListAdapter()
	{

    }
	//You should not modify
	public ArrayList<ELFUtil.Symbol> itemList()
	{
		return listViewItemList;
	}

    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
    @Override
    public int getCount()
	{
        return listViewItemList.size() ;
    }

    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
    @Override
    public View getView(int position, View convertView, ViewGroup parent)
	{
        final int pos = position;
        final Context context = parent.getContext();

        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
        if (convertView == null)
		{
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.symbol_row, parent, false);
        }

        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
		TextView addrTextView = (TextView) convertView.findViewById(R.id.symbolrowTVaddress) ;
		TextView mangledTextView = (TextView) convertView.findViewById(R.id.symbolrowTVmangled) ;
		TextView demangledTextView = (TextView) convertView.findViewById(R.id.symbolrowTVdemangled) ;
		TextView propTextView = (TextView) convertView.findViewById(R.id.symbolrowTVprop) ;
		
		{
			// Data Set(listViewItemList)에서 position에 위치한 데이터 참조 획득
			ELFUtil.Symbol listViewItem = listViewItemList.get(position);
			
			addrTextView.setText(Long.toHexString( listViewItem.st_value));
			mangledTextView.setText(listViewItem.name);
			demangledTextView.setText(listViewItem.demangled);
			try{
			propTextView.setText(listViewItem.bind.toString()+listViewItem.type.toString());
			}catch(NullPointerException e){}
		}
        return convertView;
    }

    // 지정한 위치(position)에 있는 데이터와 관계된 아이템(row)의 ID를 리턴. : 필수 구현
    @Override
    public long getItemId(int position)
	{
        return position ;
    }

    // 지정한 위치(position)에 있는 데이터 리턴 : 필수 구현
    @Override
    public Object getItem(int position)
	{
        return listViewItemList.get(position) ;
    }

	// 아이템 데이터 추가를 위한 함수. 개발자가 원하는대로 작성 가능.
    public void addItem(ELFUtil.Symbol item)
	{
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
}
//http://recipes4dev.tistory.com/m/43
