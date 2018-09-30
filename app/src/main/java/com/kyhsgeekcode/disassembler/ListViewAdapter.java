package com.kyhsgeekcode.disassembler;


import android.content.*;
import android.graphics.*;
import android.view.*;
import android.widget.*;
import java.util.*;

public class ListViewAdapter extends BaseAdapter
{
    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
    private ArrayList<ListViewItem> listViewItemList = new ArrayList<ListViewItem>() ;

    // ListViewAdapter의 생성자
    public ListViewAdapter()
	{

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
            convertView = inflater.inflate(R.layout.listview_item, parent, false);
        }

        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
		TextView addrTextView = (TextView) convertView.findViewById(R.id.tvAddr) ;
		TextView bytesTextView = (TextView) convertView.findViewById(R.id.tvBytes) ;
		TextView commentTextView = (TextView) convertView.findViewById(R.id.tvComment) ;
		TextView condTextView = (TextView) convertView.findViewById(R.id.tvCond) ;
		TextView instTextView = (TextView) convertView.findViewById(R.id.tvInst) ;
		TextView labelTextView = (TextView) convertView.findViewById(R.id.tvLabel) ;
		TextView operandTextView = (TextView) convertView.findViewById(R.id.tvOperand) ;
		//if (pos == 0)
		//{
		//	addrTextView.setTe
		//}
		//else
		{
			// Data Set(listViewItemList)에서 position에 위치한 데이터 참조 획득
			ListViewItem listViewItem = listViewItemList.get(position);
			if(listViewItem.isBranch()){
				convertView.setBackgroundColor(0xFFFF00000);
			}else{
				convertView.setBackgroundColor(Color.WHITE);
			}
			addrTextView.setText(listViewItem.getAddress());
			bytesTextView.setText(listViewItem.getBytes());
			commentTextView.setText(listViewItem.getComments());
			condTextView.setText(listViewItem.getCondition());
			instTextView.setText(listViewItem.getInstruction());
			labelTextView.setText(listViewItem.getLabel());
			operandTextView.setText(listViewItem.getOperands());
			// 아이템 내 각 위젯에 데이터 반영
			//    iconImageView.setImageDrawable(listViewItem.getIcon());
			//   titleTextView.setText(listViewItem.getTitle());
			//    descTextView.setText(listViewItem.getDesc());
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
    public void addItem(DisasmResult disasm)
	{
        ListViewItem item = new ListViewItem(disasm);
		//    item.setIcon(icon);
		// item.setTitle(title);
		//    item.setDesc(desc);
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
	// 아이템 데이터 추가를 위한 함수. 개발자가 원하는대로 작성 가능.
    public void addItem(ListViewItem item)
	{
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
}
//http://recipes4dev.tistory.com/m/43
